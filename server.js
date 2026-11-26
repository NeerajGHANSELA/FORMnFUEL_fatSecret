const express = require('express');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 4000;

// Config Toggle: Set to true only if you purchase the $250/mo NLP add-on from FatSecret
const USE_NATIVE_NLP = process.env.USE_NATIVE_NLP === 'true';

app.use(cors());

/**
 * ⚠️ THERE IS NO GLOBAL BODY PARSER, AND THAT IS DELIBERATE (M4).
 *
 * `app.use(express.json({ limit: '25mb' }))` used to sit here, and it meant
 * ANYONE on the internet could make this process buffer 25 MB per connection
 * before a single line of auth ran: the parser is mounted before the routes, so
 * it read and parsed the whole body and only then did `requireUser` answer 401.
 * Confirmed against the deployed build — a 24 MiB body with no token was read
 * in full, then refused.
 *
 * Each route mounts its own parser INSIDE its chain, after `requireUser` and
 * `requireSubscription`. An unauthenticated upload is now refused on the
 * headers and the stream is never read.
 *
 * ⚠️ THE OLD COMMENT WAS RIGHT WHEN IT WAS WRITTEN, which is why this one
 * explains what changed rather than deleting it. It said a route-level limit
 * "doesn't work" because the global parser 413s first — true, and still true:
 * the two cannot coexist, and a small global parser plus a large route-level
 * one fails exactly that way. What it could not anticipate is that the global
 * parser would stop being necessary. It was load-bearing because
 * `requireSubscription` read `req.body.operation` to decide whether to charge
 * for the call, so the body HAD to be parsed before authorisation. H1 deleted
 * that: no middleware reads the body to make an authorisation decision any
 * more, so the parser is free to move after them.
 *
 * ⚠️ 25 MB STAYS ON THE GENERATE ROUTE. `WorkoutSetupFlow` sends up to four
 * body-composition photos as base64 `inlineData` in ONE request, from pickers
 * at `quality: 0.6` with no resize step anywhere in the client — so the payload
 * is bounded by the device's camera, not by us. Whether the ceiling should be
 * lower is open and needs Gemini's actual size rule read rather than recalled:
 * its 20 MB inline limit inverts depending on whether it counts the base64
 * text or the bytes it decodes to, and 4/3 is wide enough to decide it either
 * way. Until that is read, this is the number the client was built against.
 */

/**
 * Forward a rejected async handler to the error handler below.
 *
 * ⚠️ EXPRESS 4 DOES NOT CATCH A REJECTED PROMISE, AND NODE 22 EXITS ON ONE.
 * Both are true of this process: `express ^4.19.2`, `engines.node >= 22`. So
 * an async route or middleware that throws does not return 500 — it takes the
 * whole server down, for every user, from any authenticated caller.
 *
 * Confirmed by probe: `{"ingredients":[123]}` reached
 * `(123 || '').trim()` in /api/nutrition/analyze, and the process was gone.
 * The restart also wipes `aiHits`, the in-memory limiter, so crashing the
 * server was the cheapest way to mint a fresh hourly allowance.
 *
 * ⚠️ IT COVERS MIDDLEWARE TOO, NOT JUST ROUTES. Today only
 * `requireSubscription` has a bare `await` — `requireUser` keeps its inside a
 * try, and `rateLimitAi`'s hourly path is synchronous — but the class reopens
 * the moment anyone adds an await to any of them, and wrapping costs nothing.
 *
 * ⚠️ AND IT MUST NOT SWALLOW `rateLimitAi`'s DELIBERATE FAIL-OPEN. That
 * middleware catches its own monthly failures and calls `next()` with a log
 * saying "allowing" — a cost control choosing to let the request through
 * rather than refuse on a bad read. This wrapper only sees what those catches
 * do not, so the fail-open stays a decision rather than becoming an accident
 * of plumbing. If that should ever fail CLOSED instead, change it there and
 * change its comments with it.
 */
const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------
// Every endpoint below that reaches a PAID third-party API is gated on a valid
// Supabase user token.
//
// Moving the Gemini key server-side (see /api/ai/generate) protected the KEY.
// It did nothing for the SPEND: with no auth, anyone who learned this server's
// URL could POST to it and bill our account. /api/ai/generate is deliberately a
// thin pass-through — the caller supplies the prompt, the model and the config —
// so an open deployment is not merely "an attacker can use our features", it is
// a free general-purpose Gemini endpoint charged to us, accepting 25 MB bodies.
//
// Verifying the caller's Supabase JWT rather than checking a shared secret: a
// shared secret would have to ship inside the app bundle, which is precisely
// the extraction problem the proxy was built to solve, so it would only raise
// the bar. The app already signs in to Supabase, so every real request already
// carries a token that identifies a real account — and that also makes
// per-user rate limiting possible later, which a shared secret never could.
//
// Verification goes through supabase.auth.getUser() rather than checking a
// signature locally with the JWT secret: it needs no secret on this box, it
// works whatever algorithm the project signs with, and it respects revocation
// (a locally-verified signature keeps accepting a token from a deleted or
// signed-out user until it expires).
const { createClient, isAuthRetryableFetchError } = require('@supabase/supabase-js');

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;

const supabaseAuth = SUPABASE_URL && SUPABASE_ANON_KEY
    ? createClient(SUPABASE_URL, SUPABASE_ANON_KEY, { auth: { persistSession: false, autoRefreshToken: false } })
    : null;

if (!supabaseAuth) {
    console.warn(
        '[auth] SUPABASE_URL / SUPABASE_ANON_KEY are not set — every paid endpoint will REFUSE requests. ' +
        'This is deliberate: a misconfigured proxy must fail closed, never open.',
    );
}

/**
 * Rejects anything without a valid Supabase user token.
 *
 * FAILS CLOSED. If this server is misconfigured the endpoints return 503 rather
 * than serving unauthenticated traffic — the failure mode of an auth check that
 * falls back to "allow" is an open, billable endpoint that looks fine.
 */
/**
 * Per-user rate limiting for the AI endpoint.
 *
 * The Gemini key is server-side and every caller is a verified account, so the
 * remaining exposure is a REAL account spending our money faster than a person
 * could — a script in a loop, or a token lifted out of the app bundle. Auth
 * answers "who", never "how much".
 *
 * ⚠️ THIS IS AN ABUSE CONTROL, NOT A QUOTA. The limits are set where no human
 * reaches them and a loop dies immediately. A commercial "you get N plans a
 * month" is a different feature with different failure handling: it needs a
 * visible balance and a subscription to reset against, and telling a user no
 * without either is how a paying customer decides the app is broken.
 *
 * ⚠️ THE BUCKET COUNTS THE USER'S ACTION, NOT THE CALLS IT COSTS. One diet
 * generation is a draft plus up to three day-repair rounds plus an ingredient
 * repair plus an instructions pass batched ten meals at a time — four to nine
 * requests, depending entirely on how well the model did. Counting all of them
 * against "5 diet plans an hour" would have made the allowance depend on the
 * model's luck and punished the user for its failures. Only the label the user
 * actually initiated counts against the small buckets; the rest fall to
 * MACHINERY, which is bounded transitively because none of it can run outside
 * an action that is already capped.
 */

/**
 * Which allowance each operation label spends from.
 *
 * ⚠️ THE LABEL IS CLIENT-SUPPLIED AND THEREFORE A HINT, and it is safe here for
 * one reason only: the worst a liar achieves is spending their OWN generation
 * allowance on swaps. It must never be trusted for anything that costs us
 * money — pricing belongs on measured token usage, which the client cannot
 * forge. See the app's geminiProxy call sites for where these are set.
 */
const AI_BUCKETS = {
    workout_generate: 'workout_generate',
    diet_generate: 'diet_generate',
    /**
     * ⚠️ THREE SWAP SURFACES, THREE BUCKETS, BECAUSE THEY NOW HAVE THREE
     * DIFFERENT LIMITS. They were one label on one allowance; splitting them
     * is what lets the mid-session swap be metered PER WORKOUT while the two
     * that have no workout to be counted against stay per hour. The labels are
     * also what `ai_usage.operation` records, so this buys per-surface cost
     * reporting that the single label could not give.
     */
    workout_exercise_swap: 'workout_swap',
    /**
     * ⚠️ THE SAME BUCKET AS THE SWAP IT BACKS, AND THAT CLOSES A HOLE. This is
     * the FALLBACK route, taken when the main swap cannot price a replacement
     * — and it was in no bucket at all, so it resolved to `machinery` and its
     * 120 an hour. A user whose swaps kept failing could spend well past ten
     * against a workout through this door alone, which made the per-workout
     * cap advisory rather than real.
     *
     * The same reasoning `nutrition` already records for analyze/estimate:
     * they are two halves of ONE act, and separate allowances let the pair
     * cost double what either admits to. The consequence is honest — a swap
     * that falls back spends two of the ten — because what the limit bounds is
     * calls we pay for, and a fallback is one of them.
     */
    workout_exercise_swap_estimate: 'workout_swap',
    workout_plan_swap: 'workout_plan_swap',
    workout_stuck_swap: 'workout_stuck_swap',
    diet_meal_swap: 'diet_swap',
    diet_meal_swap_named: 'diet_swap',
};

/**
 * Requests per hour, per user, per bucket.
 *
 * MACHINERY's floor is arithmetic, not taste: at these limits a user may
 * legitimately drive 5x9 + 5x2 + 15x1 + 15x1 = 85 machinery calls in an hour
 * without doing anything unusual. Set it below that and it silently becomes the
 * real limit — a user still inside their five generations gets one that dies
 * mid-repair, with no way to understand why. 120 leaves room for the paths no
 * bucket caps: prep instructions while browsing a week of meals, and tapping
 * through the manual swap sheet.
 *
 * ⚠️ SWAPS WENT 5 -> 15, AND MACHINERY HAD TO MOVE WITH THEM. Five was set
 * against no particular workflow and turned out to be below the ordinary one:
 * reviewing a freshly generated five-or-six exercise plan and replacing three
 * or four of them is what the review screen invites, and a second look an hour
 * later exhausted it. A refused swap then surfaced as "the request takes too
 * long", so the limit read as a bug.
 *
 * The raise is affordable because a swap is not a generation. Measured on the
 * real prompts: a swap sends ~700 tokens and a plan build ~3,800, so 15 swaps
 * is roughly two builds' worth against an allowance of five builds an hour.
 *
 * ⚠️ THE FLOOR ABOVE MOVED FROM 65 TO 85, which is why machinery is 120 and not
 * still 100. Leaving it at 100 would have left 15 of slack where there was 35,
 * and the first thing to break would have been a repair round inside a
 * generation the user had every right to — exactly the silent failure this
 * paragraph exists to prevent.
 */
/**
 * ⚠️ TWO WINDOWS IN ONE TABLE. The swap and machinery buckets are PER HOUR and
 * counted in memory; the two generate buckets are PER CALENDAR MONTH and
 * counted out of `ai_usage`. `MONTHLY_BUCKETS` below is what says which is
 * which, and nothing else may infer it from the number.
 *
 * A month cannot live in `aiHits`: that Map dies with the container, and this
 * service is redeployed several times on a busy day. An hourly counter losing
 * its state costs a user one extra swap; a monthly one losing it means the cap
 * never existed.
 */
/**
 * A limit, or an override from the environment.
 *
 * ⚠️ EXISTS SO A LIMIT CAN BE TESTED WITHOUT EDITING THIS FILE. Walking a
 * bucket down to 0 to watch the refusal, and then shipping the 0 because the
 * edit was never reverted, is a foreseeable way to break the app for everyone
 * — and a constant edited for a test looks identical in review to one edited
 * on purpose. `AI_LIMIT_NUTRITION=0` on the host is visibly temporary, and
 * removing it restores the real number with no commit at all.
 *
 * Anything that is not a non-negative integer is IGNORED rather than coerced:
 * a typo'd override must not silently become a limit of NaN, which compares
 * false against everything and would disable the bucket.
 */
/**
 * A non-negative integer from the environment, or the fallback — announcing
 * both the override and the typo.
 *
 * ⚠️ A BAD VALUE MUST NOT BECOME `NaN`. `Number('')` is 0 and `Number('six')`
 * is NaN, and either silently flowing into a limit or a token cap is worse
 * than the default it replaced: NaN compares false against everything, so a
 * cap of NaN is a cap of none.
 */
const envInt = (varName, fallback, announce) => {
    const raw = process.env[varName];
    if (raw === undefined || raw === '') return fallback;
    const n = Number(raw);
    if (!Number.isInteger(n) || n < 0) {
        console.warn(`${announce} ignoring ${varName}="${raw}" — want a non-negative integer`);
        return fallback;
    }
    console.warn(`${announce} OVERRIDE: ${varName} = ${n} (from env, not the default ${fallback})`);
    return n;
};

const limitFrom = (bucket, fallback) =>
    envInt(`AI_LIMIT_${bucket.toUpperCase()}`, fallback, '[ratelimit]');

const AI_LIMITS = {
    /** Per calendar month — see MONTHLY_BUCKETS. */
    workout_generate: limitFrom('workout_generate', 3),
    diet_generate: limitFrom('diet_generate', 3),

    /**
     * The HOURLY ceiling under each monthly bucket — see HOURLY_FOR_MONTHLY.
     *
     * ⚠️ THE MONTHLY BUCKETS HAD NO HOURLY LIMIT AT ALL, which is not what the
     * comments in `rateLimitAi` claimed. Every exit of its monthly block
     * returns, and `takeAiToken` is called after that block, so for these two
     * buckets it was simply unreachable. `initiated: 'app'` then returns before
     * the monthly count is even read — so one client-supplied string meant no
     * limit of any kind on the two most expensive calls in the service.
     *
     * ⚠️ THEY ARE SEPARATE ENTRIES, NOT ONE REUSED THROUGH `scope`. `scope` is
     * "the workout id for a per-workout bucket, and null everywhere else"; a
     * bucket name threaded through it would make the parameter mean two
     * unrelated things. Two entries also let the numbers move apart, and the
     * two callers are not symmetric — see below.
     *
     * ⚠️ SIX, AND THE SAME SIX ON BOTH, which is a choice rather than an
     * oversight. The hourly counter does NOT cluster retries and the monthly
     * one does: `countChargedGenerations` folds everything inside
     * RETRY_CLUSTER_MS into one charge, while `takeAiToken` counts requests —
     * so a diet phase transition that retries twice is 1 monthly and 3 hourly.
     * Six clears two full retry runs in an hour. Workout generation does not
     * retry at all, so 4 would have been safe there and was considered; it was
     * dropped because the asymmetry buys nothing against the abuse path this
     * exists to bound, and costs a second number to explain. Against the abuse
     * path, 4 and 6 are the same answer: bounded.
     */
    workout_generate_hourly: limitFrom('workout_generate_hourly', 6),
    diet_generate_hourly: limitFrom('diet_generate_hourly', 6),
    /**
     * Per WORKOUT — see PER_WORKOUT_BUCKETS. Ten swaps against the workout you
     * are actually doing, so Push, Pull and Legs each carry their own ten
     * rather than sharing one hourly pool.
     */
    workout_swap: limitFrom('workout_swap', 10),
    /** Per hour. */
    /**
     * The review screen, before a plan is saved.
     *
     * ⚠️ IT CANNOT BE PER WORKOUT, AND NOT FOR WANT OF TRYING. At this point
     * the plan exists only in the client's memory: no `workout` rows, nothing
     * in `day_assignments`, so there is no id the server can count against and
     * no id it could trust if the client invented one. Per hour is the honest
     * limit for a surface with no durable subject, and 5 is sized for
     * fine-tuning a generated plan rather than rewriting it.
     */
    workout_plan_swap: limitFrom('workout_plan_swap', 5),
    /** The plateau / "stuck" suggestion path — same reasoning, its own 5. */
    workout_stuck_swap: limitFrom('workout_stuck_swap', 5),
    diet_swap: limitFrom('diet_swap', 10),
    /**
     * ⚠️ THIS COUNTS REQUESTS TO `/api/ai/generate`, NOT GEMINI CALLS, and the
     * difference is larger than it looks. Ingredient `match` and `estimate`
     * are logged to `ai_usage` and so SHOW UP beside everything else — a cold
     * diet generation writes ~115 match rows — but they are made by
     * `pickBestFoodMatchWithAI` INSIDE a single `/api/nutrition/analyze`
     * request, and that route carries no limiter at all. They spend nothing
     * here.
     *
     * What a diet generation actually spends from this bucket is only its
     * unbucketed `/api/ai/generate` calls: ~2 repair_ingredients, ~4
     * repair_day, ~3 instructions — about 9. Three a month cannot approach
     * 120, so this stays where it was. It is a loop-breaker, not a ration.
     *
     * ⚠️ AND `/api/nutrition/*` BEING UNRATED IS A REAL GAP, just not this
     * one. Those are the highest-volume AI routes in the service — 162 calls
     * in thirteen minutes, measured — and only `requireSubscription` stands in
     * front of them. They are bounded today only because the gated actions
     * upstream (a generation, a swap) are what drive them.
     */
    machinery: limitFrom('machinery', 120),
    /**
     * `/api/nutrition/analyze` and `/api/nutrition/estimate` — FatSecret
     * ingredient pricing, the highest-volume AI route in this service and until
     * now the only one with no ceiling at all.
     *
     * ⚠️ SIZED IN REQUESTS, NOT IN THE `match` ROWS YOU SEE IN `ai_usage`.
     * `analyzeIngredientsWithFatSecret` is called ONCE PER MEAL, and each call
     * fans out inside the proxy into one `pickBestFoodMatchWithAI` per
     * ambiguous ingredient — which is how a measured generation wrote ~115
     * match rows from roughly 25 requests. Counting the rows would size this
     * five times too large.
     *
     * Legitimate worst case in one hour: ~30 requests per diet generation × the
     * 3 a month that could all land in the same hour = 90, plus ~20 for ten
     * meal swaps = ~110. 200 clears that with room while still stopping a
     * client that calls these directly in a loop, which is the hole this
     * closes.
     *
     * ⚠️ ONE BUCKET FOR BOTH ROUTES ON PURPOSE. `estimate` is the FALLBACK for
     * ingredients `analyze` could not resolve, so they are two halves of one
     * act of pricing a meal; separate allowances would let the pair cost double
     * what either admits to.
     */
    /**
     * ⚠️ THIS BUCKET COUNTS INGREDIENTS. Every other entry here counts
     * REQUESTS, and that difference is the whole of H3: these two routes were
     * metered per request at 200/hour while the work they do scales with the
     * ARRAY — up to three FatSecret searches, a Gemini match call and a
     * food.get per ingredient on /analyze, and a Gemini call per ingredient on
     * /estimate. A single legal 100 KiB body holds about 13,000 short names,
     * so 200 requests an hour authorised roughly 18 million upstream calls.
     *
     * 1,500 an hour is about thirteen full plans — a plan verifies around 115
     * ingredients — which no real user approaches; the client sends one meal
     * per request, a handful of strings each.
     *
     * ⚠️ `X-RateLimit-Remaining` FOR THIS BUCKET IS THEREFORE IN INGREDIENTS.
     * Checked before changing it: `useAiAllowance` is only ever called for
     * `workout_swap` and `diet_swap`, so no screen displays this number, and
     * `rateLimitCopy`'s fallback sentence never names a unit. If anything ever
     * does read it, that sentence has to be written before this bucket can be
     * shown.
     */
    nutrition: limitFrom('nutrition', 1500),
};

/**
 * The buckets counted per calendar month, out of `ai_usage`, rather than per
 * hour in memory.
 */
const MONTHLY_BUCKETS = new Set(['workout_generate', 'diet_generate']);

/**
 * Monthly bucket -> the hourly bucket that sits underneath it.
 *
 * ⚠️ A MISSING ENTRY FAILS OPEN, so adding a third monthly bucket and
 * forgetting this line restores the old hole silently. The assertion at the
 * bottom of this block is what refuses to let that ship.
 */
const HOURLY_FOR_MONTHLY = {
    workout_generate: 'workout_generate_hourly',
    diet_generate: 'diet_generate_hourly',
};

for (const b of MONTHLY_BUCKETS) {
    if (!HOURLY_FOR_MONTHLY[b] || AI_LIMITS[HOURLY_FOR_MONTHLY[b]] === undefined) {
        throw new Error(`[ratelimit] monthly bucket '${b}' has no hourly ceiling — add it to HOURLY_FOR_MONTHLY and AI_LIMITS`);
    }
}

/**
 * Buckets counted PER WORKOUT rather than per user — the key gains the workout
 * id, so each workout carries its own allowance.
 *
 * ⚠️ THE WINDOW IS A DAY, NOT A SESSION, and that is a deliberate
 * approximation. "Ten swaps per workout" means ten while you are doing it; a
 * session does not span midnight, so a daily window is indistinguishable from
 * per-session in practice and needs no session id threaded through the client.
 * The cost of the approximation is that two sessions of the same workout on one
 * day share an allowance, which is not a thing anyone does.
 *
 * ⚠️ AND IT FALLS BACK TO THE PER-USER KEY WHEN NO WORKOUT ID ARRIVES. An
 * unkeyed per-workout bucket would be an uncounted free pass, which is the one
 * outcome a limiter may never produce.
 */
const PER_WORKOUT_BUCKETS = new Set(['workout_swap']);

/**
 * Every `operation` label the client is allowed to send.
 *
 * ⚠️ THIS IS H1'S LESSON APPLIED TO THE OTHER HALF OF THE SAME FIELD. H1 was
 * `req.body.operation` deciding AUTHORISATION; this is the same client-chosen
 * string deciding which RATION it spends. `rateLimitAi` resolved anything it
 * did not recognise to `machinery` — 120/hour, no monthly count — so a
 * subscriber could run plan generations 120 times an hour by sending
 * `operation: 'x'`, and the `ai_usage` row recording the spend carried the
 * label they chose. An unrecognised label is now a 400, not a cheap bucket.
 *
 * ⚠️ DERIVED, NOT TRANSCRIBED. A hand-written list of the sixteen labels can
 * drift from `AI_BUCKETS` in the direction nobody tests: a label present in a
 * bucket map and absent from the list 400s a working feature in production.
 * Spreading the keys makes that unrepresentable.
 *
 * ⚠️ AND IT SPREADS `AI_BUCKETS`' KEYS, NEVER `MONTHLY_BUCKETS` OR
 * `PER_WORKOUT_BUCKETS`. Those two hold BUCKET names (`workout_swap`,
 * `diet_generate`), not operation labels, and spreading them would admit
 * strings no client sends — each resolving through `AI_BUCKETS` to `undefined`
 * and landing straight back in `machinery`, which is the hole this closes.
 *
 * The eight below are the labels that legitimately carry no bucket of their
 * own and are metered by `machinery`. Listing them turns that fall-through
 * from a silent default into a declaration: a new label is a 400 until
 * someone decides, here, which ration it spends. That is the intended cost of
 * this check — a client label shipped ahead of its server line fails loudly
 * rather than quietly buying the cheapest allowance in the table.
 */
const MACHINERY_OPERATIONS = new Set([
    'diet_generate_repair_ingredients',
    'diet_generate_repair_day',
    'diet_generate_instructions',
    'diet_prep_instructions',
    'diet_meal_swap_evaluate',
    'workout_exercise_match',
    'workout_manual_exercise_estimate',
    'body_fat_estimate',
]);

const KNOWN_OPERATIONS = new Set([...Object.keys(AI_BUCKETS), ...MACHINERY_OPERATIONS]);

/**
 * ⚠️ TWO BOOT CHECKS, AND THEY GUARD DIFFERENT THINGS.
 *
 * The first is an INVARIANT: every bucket a label maps to must have a limit.
 * Nothing checked this before, and a typo in an `AI_BUCKETS` value resolves
 * `AI_LIMITS[bucket]` to `undefined`, which makes `takeAiToken`'s comparisons
 * meaningless rather than strict — a limiter that silently stops limiting,
 * which is the one outcome it may never produce. This is the same shape as the
 * `HOURLY_FOR_MONTHLY` check above and fails only on a real mistake.
 *
 * The second is a TRIPWIRE, not an invariant: the count is a literal, so
 * adding a seventeenth label legitimately means bumping it here. That is the
 * point. The set is DERIVED, so a restructuring of `AI_BUCKETS` could shrink
 * it without touching this file's label lists, and a silently shorter
 * allow-list 400s a working feature. Growth is the more dangerous direction
 * — an extra member admits a label nobody vetted — and a count is the only
 * cheap check that sees either. Bump it deliberately; do not delete it.
 */
for (const [label, bucket] of Object.entries(AI_BUCKETS)) {
    if (AI_LIMITS[bucket] === undefined) {
        throw new Error(`[ratelimit] operation '${label}' maps to bucket '${bucket}', which has no entry in AI_LIMITS`);
    }
}

const EXPECTED_OPERATION_COUNT = 16;
if (KNOWN_OPERATIONS.size !== EXPECTED_OPERATION_COUNT) {
    throw new Error(
        `[ratelimit] KNOWN_OPERATIONS has ${KNOWN_OPERATIONS.size} labels, expected ${EXPECTED_OPERATION_COUNT}. `
        + 'If a label was added or removed on purpose, update EXPECTED_OPERATION_COUNT; otherwise something '
        + 'restructured AI_BUCKETS or MACHINERY_OPERATIONS and the allow-list no longer matches the client.'
    );
}


/**
 * How close two generate calls must be to count as ONE.
 *
 * ⚠️ THIS IS HOW "A FAILED RUN MUST NOT COUNT" IS ENFORCED WITHOUT TRUSTING
 * THE CLIENT, and it has to be done this way. `logUsage` writes a row for every
 * Gemini call that returns usage — and a failed generation's call SUCCEEDED;
 * what failed was the pipeline afterwards, on the device. Only the app knows,
 * and an app that reports its own failures can always report failure. Any
 * client-supplied "that one didn't work" fails open.
 *
 * Time tells the truth instead: a retry after a failure happens within minutes
 * by construction, a genuine second plan does not. The measured case —
 * diet_generate at 04:15:00 failing after three repair rounds and 04:26:01
 * succeeding, eleven minutes apart — collapses to one charge, while two real
 * workout plans fifteen hours apart stay two.
 *
 * ⚠️ MEASURED FROM THE CLUSTER'S FIRST CALL, NOT THE PREVIOUS ONE. Chaining it
 * off the previous call would let someone generate every nineteen minutes
 * forever on a single charge. A cluster is at most this wide, full stop.
 */
const RETRY_CLUSTER_MS = 20 * 60 * 1000;

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;

/**
 * `${userId}:${bucket}` -> { count, resetAt }.
 *
 * ⚠️ IN MEMORY, AND THAT IS A DELIBERATE STARTING POINT RATHER THAN AN
 * OVERSIGHT. A restart clears every counter, so a deploy hands everyone a fresh
 * allowance. At this scale that is a rounding error against the cost of running
 * Redis, and the failure direction is the safe one — a lost counter is a user
 * who gets five more generations, not a user locked out of an app they paid
 * for. It stops being acceptable the moment this runs on more than one
 * instance, because each would then keep its own third of the truth.
 */
const aiHits = new Map();

/**
 * Sweeps expired windows so the Map cannot grow forever.
 *
 * Without this, one entry per user per bucket accumulates for the process's
 * lifetime — slow, but unbounded, and the kind of leak that only shows up
 * months later as memory pressure on a box nobody is watching. `unref()` so a
 * pending sweep never holds the process open on shutdown.
 */
setInterval(() => {
    const now = Date.now();
    for (const [key, hit] of aiHits) {
        if (hit.resetAt <= now) aiHits.delete(key);
    }
}, HOUR_MS).unref();

/**
 * Counts one request and reports whether it may proceed.
 *
 * The window is anchored on the FIRST request in it, not on the clock hour, so
 * every user's hour starts when they start. The known weakness is the boundary
 * — five at 10:58 and five at 11:04 is ten in six minutes — which needs
 * deliberate timing, caps out at roughly double for one burst, and is what a
 * sliding window would fix if the logs ever show someone riding it.
 */
const takeAiToken = (userId, bucket, scope = null, cost = 1) => {
    const limit = AI_LIMITS[bucket];
    /**
     * An unknown bucket must never fail open into an uncounted free pass —
     * which is why `rateLimitAi` resolves anything unrecognised to 'machinery'
     * before calling this, making the line below unreachable in practice.
     *
     * ⚠️ `=== undefined`, NOT `!limit`. It was the latter, and that made a
     * limit of ZERO mean UNLIMITED: `!0` is true, so the one value anybody
     * would reach for to switch a bucket off was the one value that switched
     * the bucket off in the other direction. Nothing shipped with a 0, so this
     * never fired in production — but it is a loaded footgun for exactly the
     * person trying to test a limit.
     */
    if (limit === undefined) return { ok: true, remaining: Infinity, retryAfterSec: 0 };
    /* Per-workout buckets run on a day; everything else on an hour. Read once
       so the refusal below and the window set below cannot disagree. */
    const windowMs = PER_WORKOUT_BUCKETS.has(bucket) ? DAY_MS : HOUR_MS;

    if (limit <= 0) {
        // A deliberate 0 blocks everything, for testing the refusal paths.
        return { ok: false, remaining: 0, retryAfterSec: Math.ceil(windowMs / 1000) };
    }

    /* `scope` is the workout id for a per-workout bucket, and null everywhere
       else — see PER_WORKOUT_BUCKETS for why a missing one degrades to the
       plain per-user key rather than to no key at all. */
    const key = scope ? `${userId}:${bucket}:${scope}` : `${userId}:${bucket}`;
    const now = Date.now();
    const hit = aiHits.get(key);

    /**
     * ⚠️ ALL OR NOTHING, NEVER A PARTIAL TAKE. A request costing 60 against 40
     * remaining must be refused having spent ZERO — spending the 40 and then
     * refusing charges the caller for work that never happened and empties the
     * window on their way out. Same reason `cost > limit` refuses outright: a
     * request bigger than the whole budget can never be served, so letting it
     * drain the bucket on every attempt would be a denial of service against
     * the account rather than a limit on it.
     *
     * ⚠️ `cost` DEFAULTS TO 1, which is every other caller. Only the nutrition
     * bucket passes anything else — see AI_LIMITS.nutrition for why that one
     * counts ingredients rather than requests.
     */
    if (cost > limit) {
        return { ok: false, remaining: Math.max(0, limit - (hit?.count ?? 0)), retryAfterSec: Math.ceil(windowMs / 1000) };
    }

    if (!hit || hit.resetAt <= now) {
        aiHits.set(key, { count: cost, resetAt: now + windowMs });
        return { ok: true, remaining: limit - cost, retryAfterSec: 0 };
    }

    if (hit.count + cost > limit) {
        return {
            ok: false,
            /* The TRUE remainder, not 0 — with a cost above 1 the bucket can
               refuse while still holding headroom, and reporting 0 there would
               be a lie the client acts on. */
            remaining: Math.max(0, limit - hit.count),
            // Rounded UP: a client that retries on the second the window
            // expires races it and gets a second refusal.
            retryAfterSec: Math.max(1, Math.ceil((hit.resetAt - now) / 1000)),
        };
    }

    hit.count += cost;
    return { ok: true, remaining: limit - hit.count, retryAfterSec: 0 };
};

/**
 * The calendar month containing `now`, in UTC.
 *
 * ⚠️ UTC, NOT THE USER'S ZONE, and the consequence is worth stating: someone in
 * Toronto sees their allowance roll over at 8pm on the last day of the month,
 * not at midnight. The server has no reliable zone for the account — the phone
 * could send one, and a value that decides an allowance is a value worth lying
 * about. One predictable instant for everybody beats a per-user boundary the
 * user can move.
 */
const monthWindow = (now = new Date()) => ({
    start: new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1)),
    end: new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1)),
});

/**
 * How many generations this user has been CHARGED for this calendar month.
 *
 * Reads `ai_usage` as the user, under RLS, exactly as `flushUsage` writes it —
 * the proxy already holds their JWT, so no service-role key has to exist here.
 * The table has only INSERT and SELECT policies and deliberately no DELETE, so
 * a user cannot clear their own history to reset the cap.
 *
 * Returns null when the answer is genuinely unknown — a failed read, a missing
 * config — which the caller must not confuse with zero. See its use.
 */
const countChargedGenerations = async (token, userId, operation) => {
    if (!SUPABASE_URL || !SUPABASE_ANON_KEY || !token) return null;
    const { start, end } = monthWindow();

    const url = `${SUPABASE_URL}/rest/v1/ai_usage`
        + `?select=created_at`
        + `&user_id=eq.${encodeURIComponent(userId)}`
        + `&operation=eq.${encodeURIComponent(operation)}`
        + `&created_at=gte.${encodeURIComponent(start.toISOString())}`
        + `&order=created_at.asc`;

    let rows;
    try {
        const r = await fetch(url, {
            headers: { apikey: SUPABASE_ANON_KEY, Authorization: `Bearer ${token}` },
        });
        if (!r.ok) {
            console.warn(`[ratelimit] ai_usage read returned ${r.status} for ${operation}`);
            return null;
        }
        rows = await r.json();
    } catch (err) {
        console.warn('[ratelimit] ai_usage read failed:', err?.message || err);
        return null;
    }
    if (!Array.isArray(rows)) return null;

    /* Rows arrive oldest-first. Every row more than RETRY_CLUSTER_MS after the
       START of the open cluster begins a new one; everything inside it is the
       same generation being retried. See RETRY_CLUSTER_MS. */
    let charged = 0;
    let clusterStart = 0;
    for (const row of rows) {
        const t = Date.parse(row?.created_at);
        if (!Number.isFinite(t)) continue;
        if (charged === 0 || t - clusterStart > RETRY_CLUSTER_MS) {
            charged += 1;
            clusterStart = t;
        }
    }
    return { charged, resetAt: end };
};

/**
 * THE PER-USER MONTHLY SPEND BUDGET, in cost units — the only control in this
 * file that bounds a MONTH rather than an hour or a single call.
 *
 * ⚠️ WHY A THIRD CONTROL. The `operation` allow-list picks which burst bucket a
 * call spends from, and the part caps bound what one call can cost. Neither
 * bounds a month: `machinery` admits 120 calls an hour and the two monthly
 * buckets count GENERATIONS, not cost, so eight of the sixteen labels had no
 * monthly bound of any kind. This is what closes "cheap label, expensive
 * prompt" — whatever the label claims, the month is bounded by what the calls
 * actually cost.
 *
 * ⚠️ ONE UNIT IS ONE OUTPUT TOKEN, AND PROMPT TOKENS ARE DIVIDED RATHER THAN
 * COUNTED. Gemini bills input at a fifth of output, so a budget on raw totals
 * would be dominated by the cheap side and a photo-heavy legitimate month
 * could exhaust an allowance it barely costs — the heaviest real month on
 * record is 70k prompt against 25k out+think, a ratio of nearly three to one
 * the wrong way. Dividing makes the number a cost figure instead of a volume.
 *
 * ⚠️ THE DIVISOR IS A PRICE FACT AND WILL MOVE. gemini-3.8-flash on the
 * STANDARD rate card, read 2026-11-26: $1.50 per 1M input, $7.50 per 1M
 * output, thinking billed AS output. 7.50 / 1.50 = 5. If the card changes,
 * this is the line to change, and it is deliberately not env-driven: a wrong
 * environment value would silently distort every budget decision with nothing
 * in the log to say so.
 */
const PROMPT_UNIT_DIVISOR = 5;

/**
 * ⚠️ NOT IN `AI_LIMITS`, DELIBERATELY, and this is the trap it avoids.
 * `sendRateLimited` fills the response's `limit` from `AI_LIMITS[bucket]`, and
 * the client turns that number into prose. Every other bucket's limit counts
 * REQUESTS; this one counts token-equivalents, so publishing it would put
 * "500000" in a sentence built to say how many plans someone built. Absent
 * from the table, `limit` resolves to null and the client's copy says nothing
 * about the size — which is the honest answer, since no user can act on a
 * token figure. The budget is still logged on every refusal.
 */
const MONTHLY_UNIT_BUDGET = limitFrom('monthly_spend', 500000);

/**
 * ⚠️ ONE EXPRESSION FOR EVERY UNTRUSTED NUMBER OUT OF `ai_usage`. The table's
 * RLS allows INSERT-own, the four token columns are plain `integer NOT NULL
 * DEFAULT 0` with no CHECK, and a user can therefore insert rows under their
 * own id with NEGATIVE counts to lower any sum computed from it. Clamping per
 * ROW rather than on the total is what makes that useless: a negative row
 * contributes zero instead of subtracting. `Number.isFinite` covers null,
 * undefined and NaN in the same test, so a column that is not what the schema
 * promises cannot poison the sum either.
 *
 * A DB-level CHECK is the right home for this and is a follow-up outside this
 * repo; the clamp defends regardless of whether that ever lands.
 */
const nonNegative = (v) => (Number.isFinite(v) && v > 0 ? v : 0);

const unitsFromTokens = (promptTokens, outputTokens, thinkingTokens) =>
    nonNegative(promptTokens) / PROMPT_UNIT_DIVISOR
    + nonNegative(outputTokens)
    + nonNegative(thinkingTokens);

/**
 * userId -> { monthKey, units, seeded, seedPromise }
 *
 * ⚠️ IN MEMORY, AND IT DIES ON REDEPLOY — the same property `aiHits` has and
 * the same accepted cost. A restart reseeds from `ai_usage` on each user's
 * next call, so the figure is recovered rather than lost; what a restart
 * actually forgives is the few seconds of spend not yet flushed to the table.
 *
 * ⚠️ AND IT IS WHY THIS WORKS AT ALL. A budget read from `ai_usage` on every
 * call CANNOT bound a burst: `logUsage` buffers rows for up to USAGE_FLUSH_MS
 * (5s) or USAGE_FLUSH_ROWS (50), so concurrent calls all read a total that
 * predates every one of them. 120 concurrent requests would each see zero and
 * all pass, overshooting a 500k budget by more than an order of magnitude
 * before the first row landed. The accumulator is synchronous, so admissions
 * see each other.
 */
const monthlyUnits = new Map();

const monthKeyOf = (start) => start.toISOString().slice(0, 7);

/**
 * This user's spend so far this calendar month, in units, from `ai_usage`.
 *
 * Reads as the user under RLS with their own JWT, exactly as
 * `countChargedGenerations` does and for the same reason: no service-role key
 * exists on this box. Returns null when the answer is genuinely unknown, which
 * the caller must not confuse with zero — see `ensureMonthlyUnitsSeeded`.
 *
 * ⚠️ NO `operation` FILTER, UNLIKE `countChargedGenerations`. The whole point
 * is that the label does not bound the month, so the sum is across every
 * operation this user has been charged for — including the server-internal
 * `match` and `estimate` rows, which are real spend under this user's name.
 */
const readMonthlyUnits = async (token, userId) => {
    if (!SUPABASE_URL || !SUPABASE_ANON_KEY || !token) return null;
    const { start } = monthWindow();

    const url = `${SUPABASE_URL}/rest/v1/ai_usage`
        + `?select=prompt_tokens,output_tokens,thinking_tokens`
        + `&user_id=eq.${encodeURIComponent(userId)}`
        + `&created_at=gte.${encodeURIComponent(start.toISOString())}`;

    try {
        const r = await fetch(url, {
            headers: { apikey: SUPABASE_ANON_KEY, Authorization: `Bearer ${token}` },
        });
        if (!r.ok) {
            console.warn(`[ratelimit] ai_usage unit read returned ${r.status}`);
            return null;
        }
        const rows = await r.json();
        if (!Array.isArray(rows)) return null;
        let units = 0;
        for (const row of rows) {
            units += unitsFromTokens(row?.prompt_tokens, row?.output_tokens, row?.thinking_tokens);
        }
        return units;
    } catch (err) {
        console.warn('[ratelimit] ai_usage unit read failed:', err?.message || err);
        return null;
    }
};

/**
 * Seed this user's accumulator for this month, at most once.
 *
 * ⚠️ THE PROMISE IS CACHED, NOT THE RESULT, because the first two calls of a
 * user-month race. Both await the same promise and one DB read happens; the
 * alternative is two reads where the second overwrites whatever the first had
 * already accumulated.
 *
 * ⚠️ A FAILED SEED DELETES THE ENTRY AND NEVER WRITES `units: 0`. Writing zero
 * would hand that user a fresh month on the strength of one Supabase blip —
 * the same mistake as treating a failed read as an empty one, which is the
 * shape that bit `countChargedGenerations`. Deleting means the next request
 * retries instead of enforcing against a number nobody knows.
 *
 * ⚠️ A MONTH ROLLOVER RESEEDS, IT DOES NOT RESET TO ZERO, for that same
 * reason: the new month's real spend is whatever the table says, and on the
 * first of the month that is usually zero but is not guaranteed to be.
 */
const ensureMonthlyUnitsSeeded = (token, userId) => {
    if (!userId) return Promise.resolve(false);
    const monthKey = monthKeyOf(monthWindow().start);

    let entry = monthlyUnits.get(userId);
    if (entry && entry.monthKey !== monthKey) {
        monthlyUnits.delete(userId);
        entry = undefined;
    }
    if (entry) return entry.seedPromise || Promise.resolve(entry.seeded);

    const fresh = { monthKey, units: 0, seeded: false, seedPromise: null };
    fresh.seedPromise = (async () => {
        const seeded = await readMonthlyUnits(token, userId);
        if (seeded === null) {
            /* Only drop the entry if it is still ours — a rollover during the
               read would otherwise delete the new month's fresh one. */
            if (monthlyUnits.get(userId) === fresh) monthlyUnits.delete(userId);
            console.warn(`[ratelimit] monthly spend unknown for ${userId}, allowing`);
            return false;
        }
        fresh.units += seeded;
        fresh.seeded = true;
        fresh.seedPromise = null;
        return true;
    })();

    monthlyUnits.set(userId, fresh);
    return fresh.seedPromise;
};

/** The live entry, or null when there is nothing to enforce against. */
const seededEntry = (userId) => {
    const entry = monthlyUnits.get(userId);
    if (!entry || !entry.seeded) return null;
    return entry.monthKey === monthKeyOf(monthWindow().start) ? entry : null;
};

/**
 * Check and reserve in ONE synchronous step.
 *
 * ⚠️ NOTHING MAY AWAIT BETWEEN THE READ AND THE WRITE. That gap is the whole
 * burst hole this mechanism exists to close: two concurrent admissions that
 * both read before either writes both pass. The seed is awaited by the CALLER,
 * before this runs, precisely so this function can stay synchronous.
 *
 * Returns `{ ok: true, token: null }` when the user is unseeded — fail open,
 * because the hourly ceilings still bound them and a Supabase outage must not
 * read as a quota.
 */
const reserveMonthlyUnits = (userId) => {
    const entry = seededEntry(userId);
    if (!entry) return { ok: true, token: null, units: 0 };

    if (entry.units + RESERVE_PER_ATTEMPT > MONTHLY_UNIT_BUDGET) {
        return { ok: false, token: null, units: entry.units };
    }
    entry.units += RESERVE_PER_ATTEMPT;
    return {
        ok: true,
        units: entry.units,
        token: { userId, monthKey: entry.monthKey, reserved: RESERVE_PER_ATTEMPT, released: false },
    };
};

/**
 * Give back the reservation. Idempotent, and safe to call for a request that
 * never spent anything.
 *
 * ⚠️ REGISTERED ON `res.on('close')`, WHICH FIRES FOR EVERY RESPONSE — abort
 * and normal finish alike (measured: on a completed request it lands after
 * `finish`, with `writableEnded` true). A request-level `finally` was the
 * other candidate and it LEAKS: the handler's try block sits after two early
 * returns, so a missing-API-key 500 would never reach it, and a leaked
 * reservation inflates that user's month invisibly until the process restarts.
 *
 * ⚠️ IT RELEASES, AND IT MUST NOT CHARGE. Charging the reservation here would
 * DOUBLE-COUNT every abandoned generation, which is the commonest failure mode
 * on the diet draft: the upstream fetch carries no AbortSignal, so when the
 * app's 180s deadline fires the Gemini call keeps running and `logUsage`
 * settles the real figure afterwards. Close releases, completion settles, and
 * the two never describe the same tokens.
 */
const releaseMonthlyUnits = (token) => {
    if (!token || token.released) return;
    token.released = true;
    const entry = monthlyUnits.get(token.userId);
    if (!entry || entry.monthKey !== token.monthKey) return;
    entry.units = Math.max(0, entry.units - token.reserved);
};

/**
 * Add measured spend. Called from `logUsage`, so every billed call settles
 * once — including the server-internal match and estimate calls, which resolve
 * their user from `callerContext` and are real spend under that user's name.
 *
 * Silently does nothing for an unseeded user: there is no total to add to, and
 * the next seed reads the figure out of the table instead.
 */
const settleMonthlyUnits = (userId, units) => {
    if (!(units > 0)) return;
    const entry = seededEntry(userId);
    if (!entry) return;
    entry.units += units;
};


/**
 * The monthly-spend refusal. Mirrors `allowUnderHourlyCeiling`'s header
 * handling for the same reasons documented there: the headers name the bucket
 * that actually refused, and `X-RateLimit-Reset` is dropped because a month
 * date on it would overwrite the client's stored per-bucket allowance.
 */
const refuseMonthlySpend = (req, res, label, units) => {
    const { end } = monthWindow();
    const retryAfterSec = Math.max(1, Math.ceil((end.getTime() - Date.now()) / 1000));
    console.warn(
        `[ratelimit] ${req.userId} exhausted monthly_spend — `
        + `${Math.round(units)} of ${MONTHLY_UNIT_BUDGET} units (label=${label ?? 'none'})`
    );
    res.removeHeader('X-RateLimit-Reset');
    res.setHeader('X-RateLimit-Bucket', 'monthly_spend');
    res.setHeader('X-RateLimit-Window', 'month');
    res.setHeader('X-RateLimit-Remaining', '0');
    return sendRateLimited(req, res, {
        bucket: 'monthly_spend',
        label,
        window: 'month',
        retryAfterSec,
        extra: { resetAt: end.toISOString() },
    });
};


/**
 * The middleware. Runs AFTER requireUser, which is what puts `req.userId` here.
 *
 * ⚠️ AN UNRECOGNISED OR MISSING LABEL FALLS TO MACHINERY rather than being
 * refused. Builds already in testers' hands send no `operation` at all, and
 * refusing them would break the app on every phone that has not taken the
 * update — a limit nobody asked for, applied to people who cannot act on it.
 * Machinery is generous enough that an old build behaves normally and still
 * cannot loop.
 */
/**
 * The one 429 body, shared by every limiter so the shape cannot drift.
 *
 * `code` so the app can branch without parsing prose, `bucket` so it can pick
 * the right copy, `window` so it knows whether to say "this hour" or name a
 * date — the old body said neither and the app's refusal strings hardcode "in
 * the past hour" for every bucket, which a monthly cap would turn into "you
 * can build another in about 43200 minutes".
 *
 * `limit` is here because the app has been reading `error.limit` since its
 * rate-limit copy was written and never once received it, falling back to its
 * own stale duplicate of this table every time.
 */
const sendRateLimited = (req, res, { bucket, label, window, retryAfterSec, extra }) => {
    console.warn(`[ratelimit] ${req.userId} exhausted ${bucket} (label=${label ?? 'none'}, window=${window})`);
    res.setHeader('Retry-After', String(retryAfterSec));
    return res.status(429).json({
        error: {
            code: 'rate_limited',
            bucket,
            window,
            retryAfterSec,
            limit: AI_LIMITS[bucket] ?? null,
            message: 'Too many requests. Try again shortly.',
            ...extra,
        },
    });
};

/**
 * The fixed-bucket hourly limiter, for routes whose bucket is known from the
 * PATH rather than from a body field. `rateLimitAi` cannot serve these: it
 * reads `req.body.operation` to choose, and these routes have no such field.
 */
/**
 * The generation config actually sent upstream, built from scratch (M5).
 *
 * ⚠️ A WHITELIST, NEVER A BLACKLIST, and the difference is the finding. The
 * old line was `{ ...(generationConfig || {}) }` — every key the client sent
 * reached Gemini, and the only one anyone had thought about was
 * `thinkingConfig`. A blacklist has to name tomorrow's parameter today;
 * copying four known keys cannot be surprised by a fifth.
 *
 * ⚠️ `responseModalities` IS THE ONE TO UNDERSTAND. It is how you ask Gemini
 * for image or audio output, which bills on a different card entirely. No
 * client sends it, nothing here could use the answer, and it was forwarded.
 *
 * ⚠️ IT IS PURE, AND NAMED, ON PURPOSE. The outbound call cannot be observed
 * without a key, so the only way to test what is forwarded is to run this
 * function directly. Config in, `{ config, warnings }` out, no I/O.
 *
 * ⚠️ IT ADDS KEYS THE CALLER DID NOT SEND — `maxOutputTokens` and
 * `candidateCount` — so the result is deliberately NOT "the client's config
 * minus the bad parts". A legitimate request is one that produces no
 * warnings, not one that comes back unchanged.
 */
const GENERATION_CONFIG_KEYS = new Set([
    'responseMimeType', 'temperature', 'maxOutputTokens', 'thinkingConfig', 'candidateCount',
]);

const buildGenerationConfig = (raw) => {
    const warnings = [];
    const note = (key, what) => warnings.push(`${key}: ${what}`);

    const isPlainObject = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
    const src = isPlainObject(raw) ? raw : {};
    if (raw !== undefined && raw !== null && !isPlainObject(raw)) {
        note('generationConfig', `was ${Array.isArray(raw) ? 'an array' : typeof raw}; treated as absent`);
    }

    const config = {};

    if (src.responseMimeType !== undefined) {
        if (ALLOWED_RESPONSE_MIME_TYPES.has(src.responseMimeType)) {
            config.responseMimeType = src.responseMimeType;
        } else {
            note('responseMimeType', `${JSON.stringify(src.responseMimeType)} is not forwarded; dropped`);
        }
    }

    /**
     * ⚠️ TYPE-CHECKED, NOT CLAMPED TO THE VALUE WE HAPPEN TO USE. Temperature
     * costs nothing — it does not change how many tokens come back — so a
     * ceiling below Gemini's own [0, 2] would be a product opinion about
     * output quality wearing a cost control's clothes, and it would silently
     * reshape a future experiment with no log line anyone would connect to it.
     */
    if (src.temperature !== undefined) {
        const t = src.temperature;
        if (typeof t === 'number' && Number.isFinite(t) && t >= 0 && t <= 2) {
            config.temperature = t;
        } else {
            note('temperature', `${JSON.stringify(t)} is outside [0, 2] or not a number; dropped`);
        }
    }

    /**
     * ⚠️ IMPOSED WHEN ABSENT, which is the half a clamp alone would miss: of
     * every caller in the app exactly one sets this (the diet main draft, at
     * the cap), so clamping only what arrives would leave "just omit the key"
     * as the way round it, bounded by whatever Google defaults to rather than
     * by us.
     *
     * Imposing it cannot raise real spend, and the reason is worth keeping:
     * `maxOutputTokens` is a CEILING, not a target — a model that finishes
     * early is unaffected by a higher one. If any call were truncating at
     * Google's default today its JSON would not parse and the feature would be
     * visibly broken, which it is not. So nothing legitimate is sitting at the
     * limit, and raising it changes nothing except that the route now has one
     * known maximum instead of "ours, or whatever Google decided".
     */
    const maxOut = src.maxOutputTokens;
    if (maxOut === undefined) {
        config.maxOutputTokens = GEMINI_MAX_OUTPUT_TOKENS;
    } else if (Number.isInteger(maxOut) && maxOut >= 1) {
        config.maxOutputTokens = Math.min(maxOut, GEMINI_MAX_OUTPUT_TOKENS);
        if (maxOut > GEMINI_MAX_OUTPUT_TOKENS) {
            note('maxOutputTokens', `${maxOut} clamped to ${GEMINI_MAX_OUTPUT_TOKENS}`);
        }
    } else {
        config.maxOutputTokens = GEMINI_MAX_OUTPUT_TOKENS;
        note('maxOutputTokens', `${JSON.stringify(maxOut)} is not a positive integer; using ${GEMINI_MAX_OUTPUT_TOKENS}`);
    }

    /**
     * ⚠️ A BUDGET OF 0 IS A REAL ANSWER AND MUST SURVIVE. It means "no
     * thinking", which is the cheapest a call can be — and `!budget` is true
     * for it, so any falsy test silently replaces the cheapest request with
     * the 1024 default. `takeAiToken` carries the same warning about `!limit`
     * versus `limit === undefined`; this is that trap in a second place.
     */
    let budget = DEFAULT_THINKING_BUDGET;
    const tc = src.thinkingConfig;
    if (tc !== undefined) {
        if (!isPlainObject(tc)) {
            note('thinkingConfig', `was ${Array.isArray(tc) ? 'an array' : typeof tc}; using the default budget`);
        } else if (tc.thinkingBudget !== undefined) {
            const b = tc.thinkingBudget;
            if (Number.isInteger(b) && b >= 0) {
                budget = Math.min(b, GEMINI_MAX_THINKING);
                if (b > GEMINI_MAX_THINKING) {
                    note('thinkingConfig.thinkingBudget', `${b} clamped to ${GEMINI_MAX_THINKING}`);
                }
            } else {
                note('thinkingConfig.thinkingBudget', `${JSON.stringify(b)} is not a non-negative integer; using ${DEFAULT_THINKING_BUDGET}`);
            }
        }
    }
    /**
     * `includeThoughts` is never read from the client: thoughts are output
     * this proxy would carry back to a caller that ignores them.
     *
     * ⚠️ IT WARNS ONLY WHEN THE CALLER ASKED FOR TRUE. The diet main draft
     * sends `includeThoughts: false` explicitly, so warning on mere presence
     * would log on every real diet generation and destroy the property the
     * rest of this function is built on — that a legitimate request produces
     * no warnings at all. Overriding `false` with `false` is not an override.
     */
    if (isPlainObject(tc) && tc.includeThoughts !== undefined && tc.includeThoughts !== false) {
        note('thinkingConfig.includeThoughts', `${JSON.stringify(tc.includeThoughts)} is not forwarded; forced to false`);
    }
    config.thinkingConfig = { thinkingBudget: budget, includeThoughts: false };

    /* The handler reads `candidates[0]` and nothing else, so any other count
       is output we pay for and then discard. Set explicitly rather than left
       to the default, so the forwarded body states its own bound. */
    if (src.candidateCount !== undefined && src.candidateCount !== 1) {
        note('candidateCount', `${JSON.stringify(src.candidateCount)} is not forwarded; forced to 1`);
    }
    config.candidateCount = 1;

    for (const key of Object.keys(src)) {
        if (!GENERATION_CONFIG_KEYS.has(key)) {
            note(key, 'is not a forwarded parameter; dropped');
        }
    }

    return { config, warnings };
};

/**
 * The per-call INPUT caps for `/api/ai/generate` — the only thing bounding
 * what one request can cost on the prompt side.
 *
 * ⚠️ THIS IS THE AXIS `buildGenerationConfig` DOES NOT TOUCH, and it was the
 * larger of the two. That function clamps output and thinking to 32768 + 4096,
 * so a reply has cost a bounded ~$0.28 since it shipped. The prompt had no cap
 * at all: `promptChars` was computed in the handler and only ever LOGGED, so
 * the sole bound on input was the body parser and Gemini's own context window
 * — two to three orders of magnitude above anything this app sends. The
 * largest prompt in `ai_usage`, across every row ever written, is 3,093
 * tokens. Input is five times cheaper per token and was the bigger exposure
 * purely because its ceiling was looser.
 *
 * ⚠️ THE PARSER LIMIT IS NOT THIS BOUND AND MUST NOT BE LOWERED TO ACT LIKE
 * ONE. 25 MiB is sized for PHOTOS: four call sites send up to four body photos
 * as base64 `inlineData` in a single request — WorkoutSetupFlow twice (plan
 * generation at 5959 and body-fat estimate at 4184), DietSetupFlow's
 * generation at 5483, and `bodyComposition.ts` at 334 with one. Two of those
 * read the photo back from Supabase Storage rather than the 0.6-quality
 * picker, so the bytes are a stored 0.8-quality original. A text-sized body
 * limit 413s every one of them. The parser bounds MEMORY; these bound COST.
 *
 * ⚠️ TEXT IS CAPPED IN CHARACTERS, NOT TOKENS, deliberately. The route holds
 * the character count for free, and tokens-per-character is bounded above by
 * roughly 1 even for dense Unicode, so a character cap is a valid token bound
 * in the only direction that matters. An exact count would cost a tokenizer or
 * a `countTokens` round trip on the hot path to refine a number already ten
 * times the observed maximum.
 *
 * ⚠️ 128 KiB IS A JUDGEMENT AND DELIBERATELY NOT 64. The measured maximum is
 * ~12 KB of characters, which makes 64 KiB a five-times headroom on paper —
 * but `ai_usage` holds rows for only 6 of the 16 labels, so the prompts of the
 * other 10 (`workout_plan_swap`, `diet_meal_swap`, the repairs) are UNMEASURED,
 * and any of them may embed an existing plan as context. The security
 * difference between 64 KiB and 128 KiB is about $0.024 a call; the difference
 * in risk is whether a real rebuild 400s in production. Tighten it once there
 * are rows for every label, not before.
 */
const MAX_PROMPT_CHARS = 128 * 1024;
const MAX_IMAGE_PARTS = 4;
const MAX_IMAGE_B64_CHARS = 6 * 1024 * 1024;
const MAX_CONTENTS_ENTRIES = 8;
const MAX_PARTS_TOTAL = 16;
const ALLOWED_INLINE_MIME = new Set(['image/jpeg', 'image/png']);

/**
 * The generate route's body limit, in bytes, as the single source of truth.
 *
 * A number rather than `'25mb'` so the assertion below can be exact against
 * the same value the parser gets. `bytes.parse` returns a number unchanged, so
 * this is byte-identical to the string it replaces — verified, not assumed.
 */
const GENERATE_BODY_LIMIT_BYTES = 25 * 1024 * 1024;

/**
 * ⚠️ NO SHAPE MAY PASS THE PART CAPS AND THEN FAIL THE PARSER. A body refused
 * by `express.json` never reaches `validateAiRequest`, so it gets a bare 413
 * instead of a 400 naming the cap it broke — a worse outcome for a legitimate
 * four-photo upload than for any attacker. The slack covers the JSON around
 * the payload (keys, quotes, commas, `generationConfig`, `model`, `operation`),
 * which the part caps do not count; 64 KiB is ~90x the ~700 bytes 16 parts of
 * scaffolding actually costs.
 *
 * This is the line that enforces the claim. The comment above it is not.
 */
const PART_CAP_SLACK_BYTES = 64 * 1024;
if (MAX_IMAGE_PARTS * MAX_IMAGE_B64_CHARS + MAX_PROMPT_CHARS + PART_CAP_SLACK_BYTES >= GENERATE_BODY_LIMIT_BYTES) {
    throw new Error(
        '[gemini] the part caps admit more than the body parser accepts, so a legal request would 413 '
        + 'instead of being refused by name. Raise GENERATE_BODY_LIMIT_BYTES or lower the caps.'
    );
}

/**
 * What `/api/ai/generate` accepts, checked before any ration is spent.
 *
 * ⚠️ IT SITS BEFORE `rateLimitAi`, which is the ordering H3 established for
 * `validateIngredients`: metering a request we are about to refuse lets an
 * attacker empty a subscriber's hour with bodies that never reach Gemini, at
 * no cost to themselves. Shape first, ration second.
 *
 * ⚠️ SYNCHRONOUS, SO IT NEEDS NO `wrap` — same reason `validateIngredients`
 * is used bare on the nutrition routes. See the note above `express.json` on
 * the route for which middleware there do need it.
 */
const validateAiRequest = (req, res, next) => {
    const operation = req.body?.operation;
    if (typeof operation !== 'string' || !KNOWN_OPERATIONS.has(operation)) {
        /* The label is named in the LOG and not in the response: a client
           guessing at labels should learn nothing about which guesses are
           warmer. The log line is what makes a missing server line obvious. */
        console.warn(`[gemini] ${req.userId} unknown operation ${JSON.stringify(operation)} on ${req.path}`);
        return res.status(400).json({ error: { message: 'Unknown operation.' } });
    }

    const bad = (message) => {
        console.warn(`[gemini] ${req.userId} ${operation} — refused: ${message}`);
        return res.status(400).json({ error: { message } });
    };

    const { contents } = req.body || {};
    if (!Array.isArray(contents) || contents.length === 0) {
        /* The same wording the handler used before this middleware existed, so
           a client already handling that string sees no change. */
        return bad('Request must include a non-empty "contents" array.');
    }
    if (contents.length > MAX_CONTENTS_ENTRIES) {
        return bad(`"contents" must contain at most ${MAX_CONTENTS_ENTRIES} entries.`);
    }

    let textChars = 0;
    let imageParts = 0;
    let totalParts = 0;

    for (const entry of contents) {
        /* ⚠️ THE ENTRY'S OWN KEYS ARE NOT POLICED, only its parts. `role` is
           legal Gemini and no sender uses it today; refusing unknown keys here
           would break the first one to add it and buy nothing, because an
           entry carries no payload of its own. Cost lives in the parts. */
        if (!entry || typeof entry !== 'object' || !Array.isArray(entry.parts)) {
            return bad('Each "contents" entry must have a "parts" array.');
        }
        for (const part of entry.parts) {
            if (!part || typeof part !== 'object') return bad('Each part must be an object.');

            totalParts += 1;
            if (totalParts > MAX_PARTS_TOTAL) {
                return bad(`A request may contain at most ${MAX_PARTS_TOTAL} parts.`);
            }

            const hasText = Object.prototype.hasOwnProperty.call(part, 'text');
            const hasInline = Object.prototype.hasOwnProperty.call(part, 'inlineData');

            /* ⚠️ EXACTLY ONE RECOGNISED KIND, AND NOTHING ELSE — a whitelist,
               because it is the only form of this check that stays correct
               when Gemini adds the next part type. `fileData` is the one it
               refuses by name in spirit: a `fileUri` is how a caller makes
               Gemini fetch and bill a file this proxy never saw and cannot
               size. `functionCall`, `functionResponse` and `executableCode`
               are the same problem in other clothes. */
            if (Object.keys(part).length !== 1 || (!hasText && !hasInline)) {
                return bad('Each part must contain exactly one of "text" or "inlineData".');
            }

            if (hasText) {
                if (typeof part.text !== 'string') return bad('"text" must be a string.');
                textChars += part.text.length;
                if (textChars > MAX_PROMPT_CHARS) {
                    return bad(`The prompt must be at most ${MAX_PROMPT_CHARS} characters.`);
                }
                continue;
            }

            const inline = part.inlineData;
            if (!inline || typeof inline !== 'object') return bad('"inlineData" must be an object.');
            if (!ALLOWED_INLINE_MIME.has(inline.mimeType)) {
                return bad('"inlineData.mimeType" must be image/jpeg or image/png.');
            }
            if (typeof inline.data !== 'string') return bad('"inlineData.data" must be a base64 string.');
            if (inline.data.length > MAX_IMAGE_B64_CHARS) {
                return bad(`Each image must be at most ${MAX_IMAGE_B64_CHARS} base64 characters.`);
            }

            imageParts += 1;
            if (imageParts > MAX_IMAGE_PARTS) {
                /* ⚠️ COUNT, NOT BYTES, IS THE COST BOUND HERE. Gemini bills an
                   image by tile count derived from its dimensions, so a small
                   file is not a cheap image and the byte cap above is a
                   memory sanity bound, not a price one. Four is what every
                   sender sends at most — the front/back/left/right slots. */
                return bad(`A request may contain at most ${MAX_IMAGE_PARTS} images.`);
            }
        }
    }

    return next();
};


/**
 * @param costOf optional `(req) => number`. Omitted, every request costs 1,
 *               which is what "fixed" meant when this only served one shape.
 *               The nutrition routes pass the INGREDIENT count, because that
 *               is what the request actually spends upstream — see
 *               `validateIngredients`, which computes it before this runs so
 *               that a request this limiter would reject has already been
 *               rejected for being malformed, and never charges for it.
 */
const rateLimitFixed = (bucket, costOf) => async (req, res, next) => {
    /**
     * ⚠️ IT CHECKS THE MONTHLY BUDGET BUT DOES NOT RESERVE AGAINST IT, and
     * the asymmetry with `rateLimitAi` is deliberate. One nutrition request
     * fans out INSIDE the handler into a Gemini call per ambiguous ingredient
     * — up to MAX_INGREDIENTS of them — so a reservation sized for the worst
     * case would refuse legitimate meals outright. Each of those calls settles
     * its own measured units through `logUsage` as it completes, so the month
     * is still counted; what is missing is only the in-flight reservation, and
     * the 200/hour bucket below is what bounds the burst.
     *
     * ⚠️ AND IT IS ASYNC SO THE SEED CAN HAPPEN HERE. Checking only when
     * already seeded would fail open for a client that hits these routes
     * without ever touching an AI route — which is precisely the direct-loop
     * case the hourly bucket exists for.
     */
    const caller = callerContext.getStore();
    await ensureMonthlyUnitsSeeded(caller?.token, req.userId);
    const spent = seededEntry(req.userId);
    if (spent && spent.units >= MONTHLY_UNIT_BUDGET) {
        return refuseMonthlySpend(req, res, null, spent.units);
    }

    const cost = costOf ? costOf(req) : 1;
    const { ok, remaining, retryAfterSec } = takeAiToken(req.userId, bucket, null, cost);
    res.setHeader('X-RateLimit-Bucket', bucket);
    res.setHeader('X-RateLimit-Window', 'hour');
    res.setHeader('X-RateLimit-Remaining', String(remaining));
    if (ok) return next();
    return sendRateLimited(req, res, { bucket, label: null, window: 'hour', retryAfterSec });
};

const rateLimitAi = async (req, res, next) => {
    const label = typeof req.body?.operation === 'string' ? req.body.operation : null;
    const bucket = (label && AI_BUCKETS[label]) || 'machinery';
    const limit = AI_LIMITS[bucket];

    const refuse = (window, retryAfterSec, extra) =>
        sendRateLimited(req, res, { bucket, label, window, retryAfterSec, extra });

    /**
     * THE MONTHLY SPEND BUDGET, CHECKED FIRST because it is the outermost
     * bound: once the month is spent, which bucket the label names is moot.
     *
     * ⚠️ THE AWAIT IS HERE AND NOT INSIDE THE RESERVE. `reserveMonthlyUnits`
     * must stay synchronous — an await between its read and its write is the
     * burst hole it exists to close — so the seed is awaited by the caller,
     * once per user-month, with the promise shared by concurrent first calls.
     *
     * ⚠️ A LATER REFUSAL BRIEFLY HOLDS A RESERVATION. If the hourly or
     * monthly bucket below refuses after this point, the reservation lives
     * until the response closes and is then given back. That is the safe
     * direction — a concurrent request sees slightly MORE spend than is real,
     * never less — and the refusal itself still consumes no hourly token.
     */
    const spendCaller = callerContext.getStore();
    await ensureMonthlyUnitsSeeded(spendCaller?.token, req.userId);
    const spend = reserveMonthlyUnits(req.userId);
    if (!spend.ok) return refuseMonthlySpend(req, res, label, spend.units);
    if (spend.token) res.on('close', () => releaseMonthlyUnits(spend.token));

    /**
     * The hourly ceiling under a monthly bucket. Every ALLOW path of the
     * monthly block below goes through here instead of calling `next()`.
     *
     * ⚠️ IT DOES NOT USE `refuse`. That closure captures the MONTHLY bucket,
     * and `sendRateLimited` fills `limit` from `AI_LIMITS[bucket]` — so an
     * hourly refusal routed through it would ship `window: 'hour'` beside
     * `limit: 3`, the monthly allowance, and the client renders that as "You
     * have built 3 diet plans in the past hour. You can build another in about
     * 40 minutes." Every number in that sentence is wrong. Naming the hourly
     * bucket makes `limit` resolve to the hourly figure on its own, and the
     * client falls to its generic line, which is the true one.
     *
     * ⚠️ THE HEADERS NAME THE HOURLY BUCKET TOO, and that is protective rather
     * than cosmetic: `captureAllowance` keys its store by `X-RateLimit-Bucket`,
     * so an hourly number arriving under the monthly name would overwrite the
     * "N plans left this month" the UI reads. Under its own name nothing reads
     * it, and the monthly figure survives. `X-RateLimit-Reset` is dropped for
     * the same reason — a month date on an hour refusal is simply false.
     *
     * ⚠️ `label` IS KEPT AS THE ORIGINAL OPERATION so the warn line still says
     * which call was refused rather than naming the ceiling twice.
     */
    const allowUnderHourlyCeiling = () => {
        const hourlyBucket = HOURLY_FOR_MONTHLY[bucket];
        const { ok, retryAfterSec } = takeAiToken(req.userId, hourlyBucket);
        if (ok) return next();

        res.removeHeader('X-RateLimit-Reset');
        res.setHeader('X-RateLimit-Bucket', hourlyBucket);
        res.setHeader('X-RateLimit-Window', 'hour');
        res.setHeader('X-RateLimit-Remaining', '0');
        return sendRateLimited(req, res, {
            bucket: hourlyBucket, label, window: 'hour', retryAfterSec,
        });
    };

    /**
     * ⚠️ THE WHOLE MONTHLY BRANCH IS WRAPPED, because this middleware is async
     * and Express 4 does not catch a rejected one — it would hang the request
     * rather than refuse it, which is the one outcome worse than either answer.
     * Anything unexpected in here lands in the same place a failed count does:
     * allow, and say so in the log.
     */
    if (MONTHLY_BUCKETS.has(bucket)) try {
        /**
         * ⚠️ A REBUILD THE APP ASKED FOR IS NOT THE USER SPENDING THEIR
         * ALLOWANCE. A diet phase transition regenerates the plan because the
         * cut ended — the app offers it and rebuilding is HOW the transition
         * applies — and the Coach upgrade chain does the same. Charging those
         * to a three-a-month quota takes the allowance away for work the user
         * never requested, and leaves them unable to progress a phase.
         *
         * ⚠️ IT IS THE CLIENT'S WORD, AND THE BOUND IT RELIED ON DID NOT EXIST.
         * This paragraph used to say the trade was safe because what the string
         * buys is "more generations, still under the hourly machinery ceiling".
         * There was no such ceiling: every exit of this block returns, and
         * `takeAiToken` is called after it, so for a monthly bucket it was
         * unreachable. The string bought no limit of any kind on the two most
         * expensive calls in the service. It is true now because
         * `allowUnderHourlyCeiling` makes it true.
         *
         * ⚠️ EXACTLY ONE CLIENT SITE SENDS IT, and it is narrower than this
         * comment used to claim. `DietSetupFlow.tsx` sends it on a phase
         * transition, carrying `diet_generate` and nothing else — the Coach
         * upgrade chain was named here and sends nothing. So a request
         * carrying it on `workout_generate` came from a stale build or from
         * someone poking at the API, which is the other reason the ceiling
         * belongs under this branch rather than beside it.
         */
        if (req.body?.initiated === 'app') {
            res.setHeader('X-RateLimit-Bucket', bucket);
            res.setHeader('X-RateLimit-Window', 'month');
            return allowUnderHourlyCeiling();
        }

        /* A deliberate 0 refuses without a database round trip — and without
           it the read below would run only to be ignored. Matches takeAiToken's
           own handling of 0 on the hourly side. */
        if (limit <= 0) {
            res.setHeader('X-RateLimit-Bucket', bucket);
            res.setHeader('X-RateLimit-Window', 'month');
            res.setHeader('X-RateLimit-Remaining', '0');
            const { end } = monthWindow();
            return refuse('month', Math.max(1, Math.ceil((end.getTime() - Date.now()) / 1000)),
                { resetAt: end.toISOString() });
        }

        const caller = callerContext.getStore();
        const got = await countChargedGenerations(caller?.token, req.userId, label);

        /**
         * ⚠️ A FAILED READ IS NOT ZERO, AND IT IS NOT THE LIMIT EITHER. It is
         * "cannot tell", and this fails OPEN on it — deliberately, and the same
         * way the in-memory counter already fails when a deploy clears it. The
         * cost of being wrong in this direction is one extra generation; in the
         * other it is a paying subscriber refused the thing they pay for
         * because Supabase blipped.
         *
         * ⚠️ "OPEN" IS NOT "UNBOUNDED" — AND NOW THAT IS TRUE. This sentence
         * was here before the hourly ceiling was, claiming a bound that the
         * control flow made unreachable. `allowUnderHourlyCeiling` is what it
         * was always describing, and this is the path that needs it most: a
         * Supabase outage is exactly when the monthly count stops counting.
         */
        if (!got) {
            console.warn(`[ratelimit] ${req.userId} ${bucket}: month count unavailable, allowing`);
            res.setHeader('X-RateLimit-Bucket', bucket);
            res.setHeader('X-RateLimit-Window', 'month');
            return allowUnderHourlyCeiling();
        }

        const remaining = Math.max(0, limit - got.charged);
        res.setHeader('X-RateLimit-Bucket', bucket);
        res.setHeader('X-RateLimit-Window', 'month');
        res.setHeader('X-RateLimit-Remaining', String(remaining));
        res.setHeader('X-RateLimit-Reset', got.resetAt.toISOString());

        if (got.charged >= limit) {
            return refuse(
                'month',
                Math.max(1, Math.ceil((got.resetAt.getTime() - Date.now()) / 1000)),
                { resetAt: got.resetAt.toISOString() },
            );
        }
        return allowUnderHourlyCeiling();
    } catch (err) {
        /* Same reasoning as the unavailable-count path: a throw here is the
           monthly counter going quiet, which is when the hourly one carries
           the whole load. Failing open past BOTH would be unbounded. */
        console.warn('[ratelimit] monthly check threw, allowing:', err?.message || err);
        return allowUnderHourlyCeiling();
    }

    /**
     * ⚠️ CLIENT-SUPPLIED, AND BOUNDED THE SAME WAY `operation` IS. A patched
     * client could rotate this to mint fresh allowances — but every swap it
     * bought would still be a real Gemini call behind `requireSubscription`,
     * and anyone willing to patch the binary would go after that instead. What
     * it buys legitimately is the thing the hour could not express: Push, Pull
     * and Legs each holding their own ten.
     */
    const workoutId = typeof req.body?.workoutId === 'string' && req.body.workoutId
        ? req.body.workoutId
        : null;
    const scope = PER_WORKOUT_BUCKETS.has(bucket) ? workoutId : null;
    const windowName = PER_WORKOUT_BUCKETS.has(bucket) && scope ? 'workout' : 'hour';

    const { ok, remaining, retryAfterSec } = takeAiToken(req.userId, bucket, scope);

    // Sent on every response, not only refusals: a client that can see its own
    // headroom can back off before it is told to.
    res.setHeader('X-RateLimit-Bucket', bucket);
    res.setHeader('X-RateLimit-Window', windowName);
    res.setHeader('X-RateLimit-Remaining', String(remaining));

    if (ok) return next();
    return refuse(windowName, retryAfterSec);
};

/**
 * How long an entitlement answer is trusted before we ask again.
 *
 * ⚠️ SHORT ON PURPOSE. This cache is the window in which a cancelled or expired
 * subscriber can still spend. Sixty seconds costs at most one free generation
 * and saves a database round trip on every AI call; an hour would be a free
 * afternoon. It is deliberately not tied to `expires_at`, which can be days
 * away and tells you nothing about a refund that happened ten seconds ago.
 */
const ENTITLEMENT_TTL_MS = 60_000;
const entitlementCache = new Map();

/**
 * Is this user entitled to spend our money?
 *
 * ⚠️ THIS IS THE ONLY REAL GATE, AND THE CLIENT'S CHECK IS NOT ONE. The app
 * hides buttons it thinks are unavailable, which is UX — a patched binary shows
 * them anyway. What stops a non-subscriber generating a plan is this function
 * refusing before the request reaches a paid API. Everything behind the paywall
 * costs tokens per call, so the gate belongs where the tokens are spent.
 *
 * ⚠️ AND IT READS WITH THE CALLER'S OWN TOKEN, NOT A SERVICE ROLE. The RLS
 * policy already lets a user read their own subscription, so no extra privilege
 * is needed — and a service-role key sitting in this process would bypass every
 * policy in the database if the proxy were ever compromised. Least privilege
 * costs nothing here.
 */
const isEntitled = async (userId, token) => {
    const cached = entitlementCache.get(userId);
    if (cached && cached.at > Date.now() - ENTITLEMENT_TTL_MS) return cached.ok;

    const scoped = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
        auth: { persistSession: false, autoRefreshToken: false },
        global: { headers: { Authorization: `Bearer ${token}` } },
    });

    const { data, error } = await scoped
        .from('subscriptions')
        .select('status, expires_at')
        .eq('user_id', userId)
        .maybeSingle();

    // ⚠️ AN ERROR IS NOT A YES. A failed read looks exactly like a missing row,
    // and treating "cannot tell" as entitled would hand the paid tier to anyone
    // who can make a query fail. Not cached either — the next call retries.
    if (error) {
        console.warn('[entitlement] read failed:', error.message);
        return false;
    }

    /**
     * ⚠️ THE STATUS DECIDES; THE DATE IS ASKED ONLY WHERE THE STATUS MEANS
     * "ENDING". This was `ENTITLED.includes(status) && expires_at > now`,
     * which is right for exactly one of the four live statuses:
     *
     *   grace     — a card the store is RETRYING. Its expires_at is in the
     *               past BY DEFINITION; that is what grace is. The old rule
     *               refused AI to a customer who was still paying, for days,
     *               while the app (same bug, same shape) hid their plan.
     *   active    — between a period ending and the RENEWAL webhook landing a
     *   trialing    healthy subscription reads as unpaid. Seconds, usually,
     *               but this result is CACHED for ENTITLEMENT_TTL_MS, so a
     *               refusal taken in that window outlives it.
     *   cancelled — renewal off, paid period not over. The one case the date
     *               answers, and now the only place it is asked.
     *   expired   — RevenueCat's EXPIRATION: a lapsed grace period, or Google
     *               moving an account to hold. The only "it is over".
     *
     * ⚠️ THIRD COPY OF THE RULE, AND THE OTHER TWO MOVED WITH IT:
     * my-app/src/lib/subscriptionStatus.ts (the only tested one) and the
     * database's `subscription_is_active`. This function has never called
     * that one — it reads the columns and decides for itself — so the three
     * have to be changed together or the proxy refuses to generate for
     * someone the app is showing a plan to.
     */
    const ok = !data ? false
        : data.status === 'expired' ? false
            : data.status === 'cancelled'
                ? (!!data.expires_at && new Date(data.expires_at).getTime() > Date.now())
                : ['active', 'trialing', 'grace'].includes(data.status);

    entitlementCache.set(userId, { ok, at: Date.now() });
    return ok;
};

/**
 * The middleware. Runs AFTER requireUser, which supplies `req.userId`.
 *
 * ⚠️ IT GUARDS THE SHORTCUTS, NEVER THE RECORD. Nutrition analyse/estimate
 * turn "what I ate" into macros, and a free user can still type the name,
 * calories and macros in by hand — so the paid feature is the convenience, not
 * the ability to log food. Nothing that WRITES a user's own data should ever
 * end up behind this: losing access to a subscription must never mean losing
 * access to your own training or diet history.
 *
 * ⚠️ IT IS OFF UNTIL `REQUIRE_SUBSCRIPTION` IS SET — and it IS set now. This
 * paragraph used to say there was no payment system and nobody held a
 * subscription, which was true when the flag was written and has not been
 * true since RevenueCat shipped. The boot line at the bottom of this file
 * prints which mode the process actually came up in; trust that over any
 * comment, this one included.
 *
 * ⚠️ THE TEST IS A CASE-SENSITIVE EXACT MATCH ON `'true'`. `True`, `TRUE` and
 * `1` all leave enforcement OFF, silently, with every paid operation free to
 * everyone. There is no warning for that because the flag being absent is a
 * legitimate state; the boot line is the only thing that will tell you.
 */
/**
 * ⚠️ THERE IS NO PER-OPERATION EXEMPTION, AND THAT IS THE FIX (H1).
 *
 * A `FREE_OPERATIONS` set used to sit here, naming three operations a Core
 * account was allowed to spend model tokens on. It was read from
 * `req.body.operation` — a value the CLIENT chooses — while
 * `/api/ai/generate` is a deliberate thin pass-through of `contents`. So
 * writing `"operation": "workout_exercise_classify"` on top of ANY prompt
 * bought a Gemini call with no subscription at all. A bill, not a breach: the
 * route returns model output and touches no user data.
 *
 * ⚠️ THE EXEMPTION WAS NOT WRONG WHEN IT WAS WRITTEN. Without it, turning on
 * `REQUIRE_SUBSCRIPTION` gave a Core user a 402 at the save button, after the
 * quiz, with no copy for it — the three operations really were load-bearing
 * for manual plan building. What changed is the CLIENT:
 *
 *   workout_exercise_classify         deleted outright. Tracking type is a
 *                                     control the user taps; show_rep_ceiling
 *                                     resolves from keywords and rep ranges.
 *   workout_exercise_match            Coach only. `matchExercisesByName` grew a
 *                                     third deterministic pass, so Core's
 *                                     training log still follows a rebuild
 *                                     without a model.
 *   workout_manual_exercise_estimate  was never reachable by Core — activeWorkout
 *                                     routes an unpaid account to
 *                                     ManualSwapSheet, which has no AI at all.
 *
 * ⚠️ AN OLDER CLIENT DOES NOT BREAK ON THIS, which is why it could ship ahead
 * of the app. All three call sites swallow their failures: classify falls
 * through to the style default, match is "warned, never thrown" and returns
 * [], and a 402 is indistinguishable from the timeout each already handles.
 * An old build degrades — manual exercises save as weight_reps and a rebuild
 * loses fuzzy history pairing — it does not fail.
 *
 * ⚠️ IF A FUTURE OPERATION NEEDS TO BE FREE, DO NOT REINTRODUCE THE SET. The
 * defect was not the list, it was trusting a client-supplied label to make an
 * authorisation decision on a route that forwards a client-supplied prompt.
 * Give it its own route with its own fixed prompt, or bound it so hard that
 * being free is worthless — pinned model, server-built prompt, no client
 * `generationConfig`.
 */

const requireSubscription = async (req, res, next) => {
    if (process.env.REQUIRE_SUBSCRIPTION !== 'true') return next();

    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7).trim() : null;
    if (!token) return res.status(401).json({ error: { message: 'Missing bearer token.' } });

    if (await isEntitled(req.userId, token)) return next();

    /* Names the operation, so an addition that should have been free shows up
       in the logs as itself rather than as a vague refusal.

       ⚠️ READ HERE, AND ONLY FOR THE LOG. It used to be read at the top of the
       function, where it decided whether to skip the paywall — that was H1.
       It is a client-supplied string and it no longer influences anything;
       keep it that way.

       ⚠️ AND SINCE M4 IT IS USUALLY NULL HERE, so this falls back to
       `req.path`. The parser moved after this middleware, so a 402 is answered
       before the body is read — which is the point, since it stops an
       unsubscribed account making us buffer 25 MB. The cost is that every 402
       on the generate route now logs the same path string, and WHICH operation
       a Core user keeps hitting the paywall on is no longer in the log. That
       was an H1-adjacent signal and it is a real loss. If it is wanted back,
       the answer is the client sending the operation in a HEADER, which is
       readable before any body — not moving the parser back. */
    const label = typeof req.body?.operation === 'string' ? req.body.operation : null;
    console.warn(`[entitlement] ${req.userId} refused ${label ?? req.path}: no active subscription`);
    return res.status(402).json({
        error: {
            // 402 Payment Required, and `code` so the app can open the paywall
            // rather than show a generic failure.
            code: 'subscription_required',
            message: 'This feature needs an active subscription.',
        },
    });
};

/**
 * Who is making the call, readable from anywhere beneath the request.
 *
 * ⚠️ `AsyncLocalStorage`, NOT A MODULE VARIABLE. `pickBestFoodMatchWithAI` and
 * `estimateIngredientMacrosWithAI` are plain functions several layers below the
 * handler and have no `req` — but their ~120 calls per plan are most of the
 * spend, so usage that cannot attribute them is not worth recording. A
 * module-level "current user" would be wrong the moment two requests overlap;
 * this is per-async-context and cannot interleave. Threading a userId through
 * six signatures was the alternative.
 */
const { AsyncLocalStorage } = require('node:async_hooks');
const callerContext = new AsyncLocalStorage();

/**
 * Usage rows waiting to be written.
 *
 * ⚠️ BUFFERED, BECAUSE ONE PLAN IS ~120 ROWS. Inserting each as it happens is
 * 120 round trips from EU West to Supabase per generation, on the critical path
 * of a flow already measured in minutes. Flushed on a timer or a size cap,
 * whichever comes first.
 *
 * ⚠️ AND NEVER AWAITED BY A HANDLER. Measurement must not be able to slow down,
 * fail, or break a generation — a dropped buffer costs a row of analytics, a
 * blocked insert costs a user their plan. Losses on crash are accepted.
 */
const usageBuffer = [];
const USAGE_FLUSH_ROWS = 50;
const USAGE_FLUSH_MS = 5000;
let usageFlushTimer = null;

const flushUsage = async () => {
    if (usageFlushTimer) { clearTimeout(usageFlushTimer); usageFlushTimer = null; }
    if (usageBuffer.length === 0 || !SUPABASE_URL || !SUPABASE_ANON_KEY) return;

    const batch = usageBuffer.splice(0, usageBuffer.length);
    /* Written AS THE USER, under RLS — the proxy holds their JWT already, so no
       service-role key has to exist here. Grouped by token because a batch may
       span callers, and PostgREST takes an array in one request. */
    const byToken = new Map();
    for (const { token, row } of batch) {
        if (!token) continue;
        if (!byToken.has(token)) byToken.set(token, []);
        byToken.get(token).push(row);
    }
    for (const [token, rows] of byToken) {
        try {
            const r = await fetch(`${SUPABASE_URL}/rest/v1/ai_usage`, {
                method: 'POST',
                headers: {
                    apikey: SUPABASE_ANON_KEY,
                    Authorization: `Bearer ${token}`,
                    'Content-Type': 'application/json',
                    Prefer: 'return=minimal',
                },
                body: JSON.stringify(rows),
            });
            if (!r.ok) {
                console.warn(`[AI Usage] insert returned ${r.status} for ${rows.length} row(s)`);
            }
        } catch (err) {
            console.warn('[AI Usage] insert failed:', err?.message || err);
        }
    }
};

const requireUser = async (req, res, next) => {
    if (!supabaseAuth) {
        return res.status(503).json({ error: { message: 'Server auth is not configured.' } });
    }

    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7).trim() : null;
    if (!token) {
        return res.status(401).json({ error: { message: 'Missing bearer token.' } });
    }

    try {
        const { data, error } = await supabaseAuth.auth.getUser(token);

        /**
         * ⚠️ AN UNREACHABLE AUTH SERVICE IS NOT A BAD TOKEN, and separating the
         * two is the whole point of this branch. `getUser` does NOT throw when
         * the network fails or Supabase returns a 5xx — auth-js wraps that as
         * an `AuthRetryableFetchError` and hands it back in `error`, so it fell
         * into the 401 below with everything else. The catch underneath carries
         * a comment saying "a network failure talking to Supabase is NOT
         * permission to proceed", which was the right intent attached to a
         * branch the SDK never reaches for this case.
         *
         * ⚠️ IT IS NOT A COSMETIC STATUS CHANGE. `proxyFetch` retries exactly
         * one status — 401 — by calling `refreshSession()`, and during an auth
         * outage that refresh fails too. So the client answered an outage by
         * trying to re-authenticate against the service that was down, then
         * rendered the original 401 as "You have been signed out. Please sign
         * in again to continue." The user is told their session died, and
         * signing in again cannot work until the outage ends. 503 skips the
         * refresh (`res.status !== 401` returns early) and maps to "The plan
         * service is having trouble. Please try again shortly." — true, and
         * it does not send them to a login screen that cannot help.
         *
         * A genuinely bad token is a 4xx from Supabase, is not retryable, and
         * still lands on the 401 below. Nothing changes for a revoked session.
         */
        if (error && isAuthRetryableFetchError(error)) {
            /* ⚠️ THE STATUS CARRIES THE INFORMATION, NOT THE MESSAGE. auth-js
               passes a 5xx body straight through, and Supabase's is empty — so
               a real outage logs its message as the literal "{}" while
               `status` says 503. A dead host is `status: 0, "fetch failed"`.
               Printing both is what separates "never answered" from "answered
               badly", which are different incidents. */
            console.warn(`[auth] Supabase unreachable (status ${error.status ?? '?'}): ${error.message}`);
            return res.status(503).json({ error: { message: 'Could not verify credentials.' } });
        }
        if (error || !data?.user) {
            return res.status(401).json({ error: { message: 'Invalid or expired token.' } });
        }
        // Downstream handlers and logs can attribute spend to a real account.
        req.userId = data.user.id;
        /* The token travels with the id: usage rows are written as this user so
           RLS applies, which is what keeps a service-role key off this box. */
        return callerContext.run({ userId: data.user.id, token }, () => next());
    } catch (err) {
        // A network failure talking to Supabase is NOT permission to proceed.
        console.warn('[auth] Token verification failed:', err?.message || err);
        return res.status(503).json({ error: { message: 'Could not verify credentials.' } });
    }
};

// In-memory token storage
let cachedToken = null;
let tokenExpiry = 0; // Epoch timestamp in ms

// A week's meal plan reuses the same staple foods over and over (chicken breast,
// rice, eggs, banana, etc. show up across many different meals/days). Without a
// cache, every single occurrence re-runs the full search + detail lookup against
// FatSecret even though the underlying food data never changes between them.
// These two caches live for the lifetime of the server process (cleared on
// restart) and are shared across every request, so the very first time any
// process resolves "chicken breast" it costs 2 calls - every occurrence after
// that, in this request or a later one, costs 0.
//   foodSearchCache: normalized search term -> the foods.search result (food_id/food_name)
//   foodDetailCache: food_id -> the normalized servings array from food.get
const foodSearchCache = new Map();
const foodDetailCache = new Map();

/**
 * DID FATSECRET REFUSE US, or does it simply not know this food?
 *
 * ⚠️ THOSE TWO WERE THE SAME VALUE, AND IT COST 43 HOURS. `searchFoodItem`
 * returned `null` for an IP-allowlist rejection, an expired token, an HTTP 5xx
 * AND a genuine no-match alike — so an outage arrived at the pipeline as a run
 * of foods that happen not to exist, and every meal quietly fell through to the
 * AI estimator. Users still got a plan; it was built from guessed macros. The
 * shallow /health said "ok" throughout, because credentials that EXIST are not
 * credentials that WORK.
 *
 * A refusal is recorded here so three things can tell the truth: the log gets
 * one unmistakable banner instead of twenty look-alike misses, /health reports
 * `degraded` without needing ?deep=1, and the analyze response can tell the app
 * its numbers are unverified.
 *
 * ⚠️ RECENCY, NOT A LATCH. A failure ten minutes old is not an outage — the IP
 * may have been whitelisted since, the token refreshed, the 502 passed. Anything
 * that latched until restart would keep reporting an outage that had ended, and
 * an alert that cries wolf is one nobody reads on the day it matters.
 */
const SERVICE_FAILURE_STALE_MS = 10 * 60 * 1000;
let lastServiceFailure = null;
let serviceFailureCount = 0;

function noteServiceFailure(code, message) {
    const now = Date.now();
    const isNewEpisode = !lastServiceFailure || now - lastServiceFailure.at > SERVICE_FAILURE_STALE_MS;
    lastServiceFailure = { at: now, code: code ?? null, message: message ?? 'unknown' };
    serviceFailureCount++;
    // Once per episode. The per-call errors still log via fatSecretError; this is
    // the line that says "this is not a missing food, this is the service".
    if (isNewEpisode) {
        console.error(
            '\n========================================================\n' +
            '[FatSecret] SERVICE FAILING — nutrition is now UNVERIFIED.\n' +
            `  code    : ${code ?? 'n/a'}\n` +
            `  message : ${message ?? 'unknown'}\n` +
            '  Every lookup from here falls back to AI ESTIMATES.\n' +
            '  code 21 = the caller IP is not on FatSecret\'s allowlist.\n' +
            '========================================================\n'
        );
    }
}

/** True while a refusal is recent enough to still describe the current state. */
const serviceIsDegraded = () =>
    !!lastServiceFailure && Date.now() - lastServiceFailure.at < SERVICE_FAILURE_STALE_MS;

/**
 * Retrieves a valid OAuth 2.0 access token from FatSecret.
 * Caches the token and automatically fetches a new one if it's expired or near expiration.
 */
async function getFatSecretToken() {
    const now = Date.now();
    // Use the cached token if it exists and has more than 30 seconds left before expiration
    if (cachedToken && now < tokenExpiry - 30000) {
        return cachedToken;
    }

    const clientId = process.env.FATSECRET_CLIENT_ID;
    const clientSecret = process.env.FATSECRET_CLIENT_SECRET;

    if (!clientId || !clientSecret) {
        throw new Error("Missing FATSECRET_CLIENT_ID or FATSECRET_CLIENT_SECRET in proxy environment.");
    }

    console.log(`Fetching new FatSecret OAuth 2.0 token (Native NLP Mode: ${USE_NATIVE_NLP})...`);

    // Base64 encode client_id:client_secret for Basic Authentication header
    const authHeader = 'Basic ' + Buffer.from(`${clientId.trim()}:${clientSecret.trim()}`).toString('base64');

    const params = {
        grant_type: 'client_credentials'
    };

    // If using the paid NLP endpoint, we must request the 'nlp' scope
    if (USE_NATIVE_NLP) {
        params.scope = 'nlp';
    }

    try {
        // fetchWithRetry is a hoisted function declaration defined further down in
        // this file - safe to call here since it's only invoked once a request
        // comes in, by which point the whole module has finished loading.
        const response = await fetchWithRetry('https://oauth.fatsecret.com/connect/token', {
            method: 'POST',
            headers: {
                'Authorization': authHeader,
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: new URLSearchParams(params)
        });

        if (!response.ok) {
            const errText = await response.text();
            throw new Error(`FatSecret OAuth error: ${response.status} - ${errText}`);
        }

        const data = await response.json();

        cachedToken = data.access_token;
        // data.expires_in is in seconds, convert to milliseconds
        tokenExpiry = Date.now() + (data.expires_in * 1000);

        console.log(`OAuth token successfully retrieved. Expires in ${data.expires_in} seconds.`);
        return cachedToken;
    } catch (err) {
        console.error("Error fetching OAuth token from FatSecret:", err);
        throw err;
    }
}

// Matches the trailing "(150g, max 220g)" annotation the AI is prompted to append to every
// ingredient. Stripped out before any unit/food parsing so it never pollutes the FatSecret
// search query or the unit-matching logic, and its gram figure pulled out as aiGrams so
// resolveMacros can anchor its gram-normalization on the AI's own number for this exact
// ingredient occurrence instead of the generic CONVERSIONS table guess.
//
// ⚠️ ONLY the first number is used. The annotation's "max" was parsed into an `aiMax` that
// nothing ever read - and the comment here used to claim it fed "plausibility checks", so the
// file asserted a portion guard that did not exist. What does exist is isPlausible below: a
// DENSITY ceiling (10 kcal/g), which catches a wrong serving match and not an absurd quantity.
// A right-density, wrong-quantity ingredient - "3 cups rice" meaning three quarters of one -
// is still unguarded. If that is ever worth closing, close it with a bound derived in code:
// asking the model for its own ceiling is the same trap as asking it for any other number it
// has no way to check.
//
// The regex keeps both capture groups because it has to match the whole shape to strip it.
const GRAMS_ANNOTATION_REGEX = /\(\s*([\d.]+)\s*g\s*,\s*max\s*([\d.]+)\s*g\s*\)\s*$/i;

function stripGramsAnnotation(str) {
    const match = str.match(GRAMS_ANNOTATION_REGEX);
    if (!match) return { clean: str, aiGrams: null };
    return {
        clean: str.replace(GRAMS_ANNOTATION_REGEX, '').trim(),
        aiGrams: parseFloat(match[1])
    };
}

/**
 * Helper to parse an ingredient string into a structured object containing quantity, unit, and food item name.
 */
function parseIngredient(str) {
    const { clean: withoutAnnotation, aiGrams } = stripGramsAnnotation(str.trim());
    const clean = withoutAnnotation.toLowerCase()
        .replace(/\bof\b/g, '')
        .replace(/\s+/g, ' ');

    // Match numbers at the start (including integers, decimals, and fractions like 1 1/2 or 1/2)
    const qtyRegex = /^(\d+\s+\d+\/\d+|\d+\/\d+|\d+\.\d+|\d+)\s*(.*)$/;
    const qtyMatch = clean.match(qtyRegex);

    let quantity = 1;
    let rest = clean;

    if (qtyMatch) {
        let qtyStr = qtyMatch[1];
        rest = qtyMatch[2];

        if (qtyStr.includes('/')) {
            if (qtyStr.includes(' ')) {
                const parts = qtyStr.split(/\s+/);
                const integer = parseInt(parts[0]);
                const fracParts = parts[1].split('/');
                quantity = integer + parseFloat(fracParts[0]) / parseFloat(fracParts[1]);
            } else {
                const parts = qtyStr.split('/');
                quantity = parseFloat(parts[0]) / parseFloat(parts[1]);
            }
        } else {
            quantity = parseFloat(qtyStr);
        }
    }

    const units = [
        'g', 'gram', 'grams', 'kg', 'kilogram', 'kilograms',
        'ml', 'milliliter', 'milliliters', 'oz', 'ounce', 'ounces',
        'cup', 'cups', 'tbsp', 'tablespoon', 'tablespoons', 'tsp', 'teaspoon', 'teaspoons',
        'slice', 'slices', 'piece', 'pieces', 'scoop', 'scoops',
        'large', 'medium', 'small', 'whole'
    ];

    // "whole" is ambiguous: a serving-size word ("1 whole egg") when it precedes
    // the food itself, but part of a compound food NAME ("whole wheat", "whole
    // grain", "whole milk") when it precedes one of these - in that case it must
    // stay in the food name, both for the FatSecret search (searching "whole
    // wheat roti" finds a real Generic "Roti" entry; the stripped "wheat roti"
    // does not - confirmed live) and because it isn't really sizing a single
    // count of anything (this exact confusion drove the CONVERSIONS['whole']
    // fallback bug fixed earlier today).
    const WHOLE_COMPOUND_FOLLOWERS = ['wheat', 'grain', 'grains', 'milk'];
    const isWholeCompound = (w) => w[0] === 'whole' && WHOLE_COMPOUND_FOLLOWERS.includes(w[1]);

    let unit = null;
    let food = rest;

    const words = rest.split(/\s+/);
    if (words.length > 0 && units.includes(words[0]) && !isWholeCompound(words)) {
        unit = words[0];
        food = words.slice(1).join(' ');
    } else {
        const stuckUnitRegex = /^([a-zA-Z]+)\s*(.*)$/;
        const stuckMatch = rest.match(stuckUnitRegex);
        if (stuckMatch && units.includes(stuckMatch[1]) && !isWholeCompound([stuckMatch[1], stuckMatch[2].trim().split(/\s+/)[0]])) {
            unit = stuckMatch[1];
            food = stuckMatch[2];
        }
    }

    // The food phrase is kept EXACTLY as written for the primary FatSecret search:
    // cooking-method words select genuinely different database entries with different
    // macros ("baked potato" is a real entry at ~0.1g fat/100g; stripping "baked" and
    // searching bare "potato" matched "Roasted Potato" at ~7g fat/100g - confirmed
    // live as ~29g of phantom fat in one dinner). A simplified variant with leading
    // descriptor words removed is kept ONLY as a fallback search term for when the
    // full phrase matches nothing at all.
    const fillerWords = ['cooked', 'raw', 'grilled', 'boiled', 'baked', 'fried', 'diced', 'sliced', 'chopped', 'fresh', 'organic'];
    let foodWords = food.split(/\s+/);
    while (foodWords.length > 0 && fillerWords.includes(foodWords[0])) {
        foodWords.shift();
    }
    const simplified = foodWords.join(' ');

    return {
        quantity,
        unit,
        food: food || rest,
        // Fallback-only search term; null when stripping changed nothing (or ate everything).
        foodSimplified: simplified && simplified !== food ? simplified : null,
        aiGrams
    };
}

/**
 * Extracts serving amount, unit, and macronutrient fields from the FatSecret search description string.
 * Example description: "Per 100g - Calories: 147kcal | Fat: 9.94g | Carbs: 0.77g | Protein: 12.58g"
 */
function parseFoodDescription(desc) {
    const regex = /Per\s+(.*?)\s*-\s*Calories:\s*(\d+)kcal\s*\|\s*Fat:\s*([\d.]+)g\s*\|\s*Carbs:\s*([\d.]+)g\s*\|\s*Protein:\s*([\d.]+)g/i;
    const match = desc.match(regex);
    if (!match) return null;

    const servingStr = match[1].trim();
    const calories = parseFloat(match[2]);
    const fat = parseFloat(match[3]);
    const carbs = parseFloat(match[4]);
    const protein = parseFloat(match[5]);

    const qtyRegex = /^(\d+\s+\d+\/\d+|\d+\/\d+|\d+\.\d+|\d+)\s*(.*)$/;
    const qtyMatch = servingStr.match(qtyRegex);

    let servingAmount = 1;
    let servingUnit = servingStr;

    if (qtyMatch) {
        const qtyStr = qtyMatch[1];
        servingUnit = qtyMatch[2].trim();

        if (qtyStr.includes('/')) {
            const parts = qtyStr.split('/');
            servingAmount = parseFloat(parts[0]) / parseFloat(parts[1]);
        } else {
            servingAmount = parseFloat(qtyStr);
        }
    }

    return {
        servingAmount,
        servingUnit: servingUnit.toLowerCase(),
        calories,
        fat,
        carbs,
        protein
    };
}

// Genuine measuring-unit weight approximations (in grams) - a tbsp/cup/oz is roughly the
// same weight regardless of which food it's measuring, so these are trustworthy as a
// generic conversion. Deliberately does NOT include per-food guesses (egg/banana) or
// size adjectives (large/medium/small/whole) - those aren't real unit conversions (a
// "large" egg and a "large" chicken breast aren't the same weight), and resolveMacros
// now has a strictly better source for that: pickReferenceServing reads the actual
// matched food's own real serving weight from FatSecret instead of guessing.
const CONVERSIONS = {
    'slice': 30,
    'slices': 30,
    'scoop': 30,
    'scoops': 30,
    'cup': 240,
    'cups': 240,
    'tbsp': 15,
    'tablespoon': 15,
    'tablespoons': 15,
    'tsp': 5,
    'teaspoon': 5,
    'teaspoons': 5,
    'oz': 28.35,
    'ounce': 28.35,
    'ounces': 28.35
};

/**
 * Normalizes the `servings` object from a FatSecret food.get response into a flat array,
 * since the API returns a single object (not an array) when there's only one serving.
 */
function normalizeServings(servingsObj) {
    if (!servingsObj) return [];
    const raw = Array.isArray(servingsObj.serving) ? servingsObj.serving : [servingsObj.serving];
    return raw.filter(Boolean).map(s => ({
        measurementDescription: (s.measurement_description || '').toLowerCase(),
        metricServingAmount: parseFloat(s.metric_serving_amount),
        metricServingUnit: (s.metric_serving_unit || '').toLowerCase(),
        numberOfUnits: parseFloat(s.number_of_units) || 1,
        calories: parseFloat(s.calories) || 0,
        protein: parseFloat(s.protein) || 0,
        carbs: parseFloat(s.carbohydrate) || 0,
        fat: parseFloat(s.fat) || 0
    }));
}

// Converts a metric weight/volume amount into grams so it can be compared directly against
// our own gram-based estimate of the ingredient quantity. Used both for FatSecret's own
// metric_serving_unit data (which is normalized to bare 'g'/'oz'/'ml') and for the ingredient
// string's own parsed unit, which can be any of the full/plural forms below (e.g. "0.3kg" or
// "500ml") - accepting only the bare abbreviations here previously meant kg/ml/ounce/ounces
// silently fell through to the count-based CONVERSIONS table instead (see resolveMacros),
// which has no entry for them and defaults to treating 1 unit as 100g - e.g. "500ml milk"
// was computed as 500 * 100 = 50,000g instead of ~500g, a 100x error of the same kind as the
// "200g chicken breast" unit-match bug.
function toGrams(amount, unit) {
    if (!unit || isNaN(amount)) return null;
    const u = unit.toLowerCase();
    if (u === 'g' || u === 'gram' || u === 'grams') return amount;
    if (u === 'kg' || u === 'kilogram' || u === 'kilograms') return amount * 1000;
    if (u === 'oz' || u === 'ounce' || u === 'ounces') return amount * 28.3495;
    if (u === 'ml' || u === 'milliliter' || u === 'milliliters') return amount; // approximation for the liquids we deal with here
    return null;
}

// Bare metric units aren't meaningful "unit matches" on their own (FatSecret labels its plain
// per-gram serving's measurement_description as just "g") and vague size words like "large"
// don't correspond to any real FatSecret serving unit - both must be skipped when looking for
// an exact-unit serving, or short strings like "g" end up substring-matching unrelated words
// (e.g. "large" contains the letter "g").
const GENERIC_METRIC_UNITS = ['g', 'gram', 'grams', 'ml', 'oz', 'ounce', 'ounces', 'kg', 'kilogram', 'kilograms'];
const SIZE_ADJECTIVES = ['large', 'medium', 'small', 'whole'];

function wordTokens(str) {
    return (str || '').split(/[^a-z]+/).filter(Boolean);
}

// Finds a serving whose measurement_description contains `word` as a whole token
// (not a raw substring), e.g. "cup" matches "cup, pieces or slices" but "g" does not
// match "large".
function findServingByWord(servings, word) {
    if (!word) return null;
    return servings.find(s =>
        s.measurementDescription &&
        !GENERIC_METRIC_UNITS.includes(s.measurementDescription) &&
        wordTokens(s.measurementDescription).includes(word)
    );
}

// No real food exceeds roughly this many calories per gram - pure fat/oil, the most
// energy-dense thing that exists, tops out around 9 kcal/g. A resolved match implying
// more than this is a sign the matching logic picked the wrong FatSecret serving for
// this ingredient (e.g. a "1 cup" serving matched against a quantity that was actually a
// count), not that the food is genuinely that dense - see isPlausible below.
const DENSITY_CEILING_KCAL_PER_GRAM = 10;

function isPlausible(macros, referenceGrams) {
    if (!referenceGrams || referenceGrams <= 0) return true;
    return (macros.calories / referenceGrams) <= DENSITY_CEILING_KCAL_PER_GRAM;
}

// Picks the food's natural, real-world reference serving from FatSecret's own serving
// list - e.g. "slice" for bread, "large egg" for eggs - instead of a hand-authored
// per-food-category guess. Prefers a genuine discrete/countable unit (skipping bare
// metric servings, which aren't a "serving" a person would recognize); falls back to
// the smallest metric-bearing serving when the food has no discrete unit at all (loose
// staples like rice or oil). Used downstream as the grounding for realistic-portion
// clamping, not just display.
function pickReferenceServing(servings) {
    if (!servings || servings.length === 0) return null;
    const discrete = servings.find(s =>
        s.measurementDescription &&
        !GENERIC_METRIC_UNITS.includes(s.measurementDescription) &&
        toGrams(s.metricServingAmount, s.metricServingUnit) != null
    );
    if (discrete) {
        return {
            grams: toGrams(discrete.metricServingAmount, discrete.metricServingUnit),
            unit: discrete.measurementDescription
        };
    }
    const metric = servings.find(s => toGrams(s.metricServingAmount, s.metricServingUnit) != null);
    if (metric) {
        return {
            grams: toGrams(metric.metricServingAmount, metric.metricServingUnit),
            unit: 'g'
        };
    }
    return null;
}

/**
 * Resolves calories/macros for a parsed ingredient against the full list of structured
 * servings returned by food.get. Always anchors on FatSecret's own metric data (g/ml/oz)
 * instead of guessing, so scaling stays accurate regardless of what unit the AI-generated
 * ingredient string used.
 *
 * Builds every strategy's result as a candidate (rather than returning on the first hit)
 * and accepts the first one, in priority order, whose implied energy density is realistic
 * for a food (see isPlausible) - a food can have several differently-labeled servings on
 * file, and the first one a strategy reaches for isn't always the right one to trust.
 */
function resolveMacros(servings, parsedIng) {
    const ingUnit = parsedIng.unit ? parsedIng.unit.toLowerCase() : null;
    const isExplicitMetricUnit = !!ingUnit && GENERIC_METRIC_UNITS.includes(ingUnit);

    // Same estimate resolveMacros always used for gram-normalization, kept as a fallback
    // for both step 2 and the plausibility check when the AI didn't supply its own gram
    // annotation (e.g. a malformed response from an older prompt version).
    const fallbackGrams = (() => {
        const explicitMetricGrams = toGrams(parsedIng.quantity, ingUnit);
        if (explicitMetricGrams != null) return explicitMetricGrams;

        // A genuine measuring unit (tbsp/cup/oz/slice/scoop) has a roughly fixed weight
        // independent of which food it's measuring, so CONVERSIONS' per-unit entry is
        // trustworthy here. Size adjectives (large/medium/small/whole) don't have that
        // property - "whole" in "whole wheat roti" isn't even sizing the roti, it's
        // describing the flour - so they fall through to the real-data check below
        // instead of a blind size-word guess.
        if (ingUnit && !SIZE_ADJECTIVES.includes(ingUnit) && CONVERSIONS[ingUnit] != null) {
            return parsedIng.quantity * CONVERSIONS[ingUnit];
        }

        // No trustworthy unit-based conversion - FatSecret's own natural reference
        // serving for the actual matched food (real, curated per-food data) beats any
        // hardcoded guess, e.g. treating "3 rotis" as 300g instead of ~150g and
        // inflating calories 2x+ (confirmed live on this exact food).
        const reference = pickReferenceServing(servings);
        if (reference) return parsedIng.quantity * reference.grams;

        // Last resort: food.get returned no servings with any usable metric data at
        // all (rare) - nothing left to anchor on but a flat per-unit guess.
        return parsedIng.quantity * 100;
    })();
    // The AI's own per-ingredient gram estimate is a much better plausibility anchor than
    // the fallback chain above when it's actually present - it's specific to this exact
    // ingredient occurrence, not just this food in general.
    const referenceGrams = parsedIng.aiGrams != null ? parsedIng.aiGrams : fallbackGrams;

    const candidates = [];

    // 1) Exact unit match (e.g. ingredient says "egg"/"slice"/"cup" and FatSecret has a
    //    serving described in that same unit) - most accurate, no gram conversion needed.
    // Try the parsed unit first (skipping generic metric units/size words, which aren't
    // real FatSecret serving units), then fall back to the food name itself (e.g. "eggs"
    // singularized to "egg") since AI-generated ingredients often use a size adjective
    // ("3 large eggs") rather than the food's natural counting unit.
    //
    // IMPORTANT: both the unit-word and food-word fallback only make sense when the
    // ingredient's quantity is itself a *count* (eggs, slices, cups...), not a real
    // gram/oz/ml measurement. If the ingredient already gives an explicit metric amount
    // (e.g. "200g cooked chicken breast"), the food-word fallback is actively dangerous:
    // it will happily match any serving whose description contains a word from the food
    // name - e.g. "chicken breast" matching a "small breast (yield after cooking, bone
    // removed)" serving - and then treat "200" as 200 of THAT serving (200 breasts)
    // instead of 200 grams, inflating the result by ~100-200x. Confirmed live: this
    // exact case turned 200g chicken breast into 65,600 kcal / 9,928g protein. When the
    // unit is an explicit metric unit, skip straight to gram-normalization (step 2) below
    // and never attempt a count-based match.
    let exact = null;
    if (!isExplicitMetricUnit) {
        if (ingUnit && !SIZE_ADJECTIVES.includes(ingUnit)) {
            exact = findServingByWord(servings, ingUnit) || findServingByWord(servings, ingUnit.replace(/s$/, ''));
        }
        if (!exact && parsedIng.food) {
            const foodWord = parsedIng.food.split(/\s+/).pop();
            exact = findServingByWord(servings, foodWord) || findServingByWord(servings, foodWord.replace(/s$/, ''));
        }
    }
    if (exact && exact.numberOfUnits > 0) {
        const scalingFactor = parsedIng.quantity / exact.numberOfUnits;
        candidates.push({
            calories: exact.calories * scalingFactor,
            protein: exact.protein * scalingFactor,
            carbs: exact.carbs * scalingFactor,
            fat: exact.fat * scalingFactor,
            via: `unit match (${exact.measurementDescription})`
        });
    }

    // 2) Normalize to grams: try EVERY serving with usable metric data (not just the
    //    first one found), scaling each using the AI's own gram estimate for the
    //    ingredient quantity - a food can carry several metric-bearing servings, and the
    //    first one reached isn't always the one that produces a sane result.
    const gramServings = servings.filter(s => toGrams(s.metricServingAmount, s.metricServingUnit) != null);
    for (const gramServing of gramServings) {
        const servingGrams = toGrams(gramServing.metricServingAmount, gramServing.metricServingUnit);
        // If the ingredient already gives a real metric weight/volume, or the AI supplied
        // its own gram annotation, that's a direct answer - use it rather than guessing
        // via the CONVERSIONS table, which is meant only as a last-resort estimate.
        const ingredientGrams = parsedIng.aiGrams != null
            ? parsedIng.aiGrams
            : fallbackGrams;
        const scalingFactor = ingredientGrams / servingGrams;
        candidates.push({
            calories: gramServing.calories * scalingFactor,
            protein: gramServing.protein * scalingFactor,
            carbs: gramServing.carbs * scalingFactor,
            fat: gramServing.fat * scalingFactor,
            via: `gram-normalized (${servingGrams.toFixed(0)}${gramServing.metricServingUnit} serving)`
        });
    }

    // 3) Last resort: no metric data at all (rare) - compare unit counts directly.
    const fallback = servings[0];
    if (fallback) {
        const scalingFactor = parsedIng.quantity / (fallback.numberOfUnits || 1);
        candidates.push({
            calories: fallback.calories * scalingFactor,
            protein: fallback.protein * scalingFactor,
            carbs: fallback.carbs * scalingFactor,
            fat: fallback.fat * scalingFactor,
            via: 'no metric data, raw unit-count fallback'
        });
    }

    // Accept the first candidate, in priority order, whose implied energy density is
    // realistic. If none pass, every strategy picked a serving that doesn't square with
    // what the AI actually meant by this ingredient - safer to report it unresolved than
    // to silently save an implausible number.
    const winner = candidates.find(c => isPlausible(c, referenceGrams));
    // referenceGrams (the real gram weight behind the ingredient's stated quantity) rides
    // along on the winning candidate so the caller can derive how many real grams equal
    // ONE unit of whatever the ingredient string's own quantity was in (a slice, an egg, a
    // gram) - needed downstream to ground realistic-portion clamping in real weight
    // regardless of which unit the AI happened to write.
    return winner ? { ...winner, referenceGrams } : null;
}

// A full week's plan can mean 100+ ingredients, each needing 2 sequential
// FatSecret calls (search + detail) - a burst like that can trip a rate limit
// or hit a transient server error even when every food is perfectly resolvable
// (confirmed: re-running the exact same ingredients alone, outside a big batch,
// resolved fine). Retry with backoff on 429/5xx rather than giving up
// immediately and marking an otherwise-normal food as unresolved.
async function fetchWithRetry(url, options, { retries = 3, baseDelayMs = 500 } = {}) {
    let lastResponse = null;
    for (let attempt = 0; attempt <= retries; attempt++) {
        const response = await fetch(url, options);
        if (response.ok) return response;

        lastResponse = response;
        const isRetryable = response.status === 429 || response.status >= 500;
        if (!isRetryable || attempt === retries) return response;

        const delay = baseDelayMs * Math.pow(2, attempt);
        console.warn(`Request returned ${response.status}, retrying in ${delay}ms (attempt ${attempt + 1}/${retries})...`);
        await new Promise(resolve => setTimeout(resolve, delay));
    }
    return lastResponse;
}

// One foods.search call, reduced to its useful outcome: the best matching food
// item, or null (HTTP failure, empty result set, or - when foodCore is given -
// zero candidates relevant enough to accept - all mean "this term found
// nothing usable" to the caller, which decides whether to retry with a
// different term).
//
// Requests several results instead of just the top one, and prefers a
// food_type "Generic" entry over a "Brand" one when both are present - a
// same-named restaurant/brand can easily outrank the actual generic food
// (confirmed live: searching the exact word "roti" returned a "Roti
// Mediterranean Grill" restaurant chain's branded pita bread as the #1
// result, ahead of any real roti/chapati entry).
//
// foodCore (optional) is the AI's own minimal, canonical name for the food's
// identity (e.g. "fresh krachai" -> "krachai", "white fish fillet" -> "white
// fish") - every one of its words must appear in a candidate's name
// (singular/plural-insensitive) before that candidate can be accepted, for
// BOTH the "prefer Generic" step and the final fallback. This replaces a
// cruder self-derived "head word" (the search phrase's last word) as the
// relevance gate, because "last word = most distinguishing word" isn't
// reliable: confirmed live, foods.search("fresh krachai") returns Fresh Ham,
// Fresh Lime Juice, Fresh Asiago Cheese etc. - none contain "krachai," they
// only coincidentally share "fresh" - and foods.search("white fish fillet")
// returns several branded "Fish Stick Patty or Fillet" products that all
// contain "fillet" yet are the wrong food entirely. Only the AI that wrote
// the ingredient string actually knows which words are the food's real
// identity vs. just modifiers, so when foodCore is available there is no
// blind fallback: if nothing in the top results passes the gate, this
// returns null exactly like an empty search would, letting the caller retry
// with a simplified term and, ultimately, trigger ingredient repair instead
// of silently accepting an unrelated food.
//
// When foodCore is missing/null (older client, or the AI omitted it), falls
// back to the original head-word-from-searchExpression heuristic unchanged,
// including its blind fallback to the top-ranked result - a branded match
// beats no match at all in that degraded mode.
//
// Word-overlap alone can't reliably tell a food apart from a manufactured
// DERIVATIVE of it that happens to share every word - FatSecret carries Generic
// entries for an oil/sauce/milk/powder/etc. version of countless base foods.
// Confirmed live: requiring "sweet"+"basil" (a real variety name, not a
// droppable modifier) matched Generic "Sweet Basil Oil" - a cooking oil at
// 429kcal/50g - ahead of the correct "Basil" leaf entry at 9kcal/50g. No fixed
// list of words to watch for generalizes to every food, so this is the
// fallback tier only (see pickBestFoodMatchWithAI below for the primary path,
// which asks the AI to judge the actual candidates directly instead of
// guessing from word overlap).
function pickFoodMatchByWords(searchExpression, foodCore, usable) {
    const tokensOf = (name) => (name || '').toLowerCase().split(/[^a-z]+/).filter(Boolean);
    const wordMatchesTokens = (word, tokens) => {
        if (tokens.includes(word)) return true;
        if (word.endsWith('s') && tokens.includes(word.slice(0, -1))) return true;
        if (!word.endsWith('s') && tokens.includes(word + 's')) return true;
        return false;
    };

    const coreWords = (foodCore || '').trim().toLowerCase().split(/\s+/).filter(Boolean);

    let nameMatches;
    if (coreWords.length > 0) {
        nameMatches = (name) => {
            const tokens = tokensOf(name);
            return coreWords.every(w => wordMatchesTokens(w, tokens));
        };
    } else {
        const searchWords = searchExpression.trim().toLowerCase().split(/\s+/).filter(Boolean);
        const headWord = searchWords[searchWords.length - 1] || '';
        nameMatches = (name) => wordMatchesTokens(headWord, tokensOf(name));
    }

    // 'powder' and 'milk' deliberately excluded: they're the normal, correct way
    // FatSecret names whole categories of real foods (protein powder, cocoa
    // powder, whole/2%/nonfat milk yogurt and cheese), not just a sign of a
    // different derived product - blindly rejecting them broke verification for
    // completely ordinary ingredients like "whey protein" and "greek yogurt".
    const PROCESSED_FORM_WORDS = ['oil', 'sauce', 'syrup', 'juice', 'extract', 'paste', 'butter', 'flour', 'dried', 'chips', 'crisps', 'jam', 'jelly', 'cream', 'concentrate', 'spread', 'flakes'];
    const ownWords = tokensOf(searchExpression);
    const isProcessedFormMismatch = (name) => {
        const tokens = tokensOf(name);
        return PROCESSED_FORM_WORDS.some(w => tokens.includes(w) && !ownWords.includes(w));
    };
    const isAcceptable = (name) => nameMatches(name) && !isProcessedFormMismatch(name);

    const genericMatch = usable.find(f => f.food_type === 'Generic' && isAcceptable(f.food_name));
    if (genericMatch) return genericMatch;

    if (coreWords.length === 0) return usable[0];

    return usable.find(f => isAcceptable(f.food_name)) || null;
}

// Deliberately a cheap/high-quota model, NOT the one the diet-plan generator
// uses. The two AI calls here (pickBestFoodMatchWithAI,
// estimateIngredientMacrosWithAI) fire ONCE PER INGREDIENT, so a single 28-meal
// plan drives ~120+ calls through this file — two orders of magnitude more
// than the whole app-side generation pipeline. Pointing this at a
// low-request-quota model exhausts the daily quota within one plan
// generation. These are simple matching/estimation tasks; Flash-Lite is the
// right tier for them regardless of what the plan generator runs on.
// Fallback only — the app names a model on every request, and the handler below
// honours it whenever it appears in ALLOWED_MODELS. This is what gets used if a
// caller sends nothing, or sends something unrecognised.
//
// ⚠️ Kept identical to the app's default in lib/geminiProxy.ts. It was
// gemini-3.1-flash-lite while the app defaulted to gemini-3.6-flash, which made
// the substitution silent AND a downgrade: an unrecognised model name would not
// fail, it would quietly answer from a weaker one. Change both together.
const GEMINI_MODEL = process.env.GEMINI_MODEL || 'gemini-3.8-flash';

/**
 * The two PER-INGREDIENT helpers run on their own models, and not the same one
 * as each other — because they are not the same kind of task.
 *
 * ⚠️ BOTH FIRE ~ONCE PER INGREDIENT, so a 28-meal plan drives ~120+ calls
 * through here — two orders of magnitude more than the whole app-side
 * generation pipeline. Neither is covered by the 404/429 fallback in the
 * handler below, so a quota refusal here is a hard failure, not a downgrade.
 * That is the constraint everything on this line answers to.
 *
 * MATCH is a classification: "which of these five FatSecret rows is the same
 * food as this string?" There is no reasoning to do and a cheap, high-quota
 * tier is the right one — the note above `GEMINI_MODEL` has said so since
 * before this constant existed.
 *
 * ESTIMATE is the opposite. It only runs when FatSecret could not price the
 * food at all, so its numbers go straight into the plan with nothing
 * downstream to check them. A weak model here does not produce a worse match,
 * it produces wrong calories the user then eats to. It stays on the capable
 * model.
 *
 * ⚠️ AND IT HAS NO `thinkingConfig`, DELIBERATELY. Thinking would suit the
 * task, but the cost is per call and there are up to 120 of them in series
 * with a 120ms pacing gap. Count `[AI Estimate]` lines in one real generation
 * first: a handful justifies thinking, dozens does not.
 */
/**
 * One greppable line per Gemini call, carrying the only numbers a price can be
 * computed from.
 *
 * ⚠️ TOKENS, NOT CHARACTERS. The existing timing lines report prompt/reply
 * CHARS, which answers "was it slow" and cannot answer "what did it cost" —
 * billing is per token, the ratio is not fixed, and thinking tokens do not
 * appear in the reply at all. `usageMetadata` comes back on every response and
 * was being discarded.
 *
 * ⚠️ `think` IS BILLED AS OUTPUT even though it never reaches the app. It is
 * broken out rather than folded into `out` precisely so the cost of
 * `thinkingConfig` is visible as its own number and can be turned off on
 * evidence.
 *
 * ⚠️ `op` IS CLIENT-SUPPLIED AND THEREFORE A HINT — see AI_BUCKETS above. Safe
 * for measurement, where the worst a liar does is mislabel their own spend.
 * Never bill from it.
 *
 * Format is deliberately key=value so a week of Railway logs can be summed by
 * operation with a one-line script rather than read by eye.
 */
const logUsage = (op, modelName, data, elapsedMs) => {
    const u = (data && data.usageMetadata) || {};
    const think = u.thoughtsTokenCount || 0;
    console.log(
        `[AI Usage] op=${op} model=${modelName} ` +
        `in=${u.promptTokenCount ?? '?'} out=${u.candidatesTokenCount ?? '?'} ` +
        `think=${think} total=${u.totalTokenCount ?? '?'} ms=${elapsedMs}`
    );

    /**
     * The same numbers, somewhere they survive.
     *
     * ⚠️ THE LOG LINE STAYS. It is what you read while a generation is running;
     * the table is what you query a month later. Retention is the difference:
     * Railway keeps 7 days and drops lines under exactly the burst one plan
     * produces.
     *
     * ⚠️ NO ROW WITHOUT A CALLER. An unattributed row cannot answer "what does
     * this user cost", which is the only question worth storing it for.
     */
    const caller = callerContext.getStore();
    if (!caller?.userId || !caller?.token) return;

    /**
     * ⚠️ SETTLE HERE, WHICH MEANS A NON-OK ATTEMPT IS CHARGED NOTHING. This
     * function is only called when Gemini answered ok, and a non-ok response
     * carries no `usageMetadata` to settle from anyway. That is the intended
     * reading: an attempt that produced no output cost nothing, and probing
     * for refusals is already bounded by the burst token spent at admission.
     *
     * ⚠️ IT IS WHERE SETTLE BELONGS RATHER THAN THE HANDLER, because the
     * server-internal `match` and `estimate` calls come through here too —
     * they resolve their user from `callerContext` and are real spend under
     * that user's name. Settling in the generate handler would miss both, and
     * they are the highest-volume calls in the service.
     */
    settleMonthlyUnits(
        caller.userId,
        unitsFromTokens(u.promptTokenCount, u.candidatesTokenCount, think),
    );

    usageBuffer.push({
        token: caller.token,
        row: {
            user_id: caller.userId,
            operation: op,
            model: modelName,
            prompt_tokens: u.promptTokenCount ?? 0,
            output_tokens: u.candidatesTokenCount ?? 0,
            thinking_tokens: think,
            total_tokens: u.totalTokenCount ?? 0,
            elapsed_ms: elapsedMs,
        },
    });

    if (usageBuffer.length >= USAGE_FLUSH_ROWS) {
        void flushUsage();
    } else if (!usageFlushTimer) {
        usageFlushTimer = setTimeout(() => { void flushUsage(); }, USAGE_FLUSH_MS);
        /* Must not keep the process alive on its own account. */
        if (usageFlushTimer.unref) usageFlushTimer.unref();
    }
};

const MATCH_MODEL = process.env.GEMINI_MATCH_MODEL || 'gemini-3.5-flash-lite';
const ESTIMATE_MODEL = process.env.GEMINI_ESTIMATE_MODEL || 'gemini-3.8-flash';

/**
 * How much reasoning each per-ingredient call may spend.
 *
 * ⚠️ A CEILING, NOT A SPEND. The model uses what the task needs and stops; this
 * bounds the worst case. So the numbers are sized by "what could this task
 * plausibly need" multiplied by how many times it runs, not by how clever we
 * would like the answer to be.
 *
 * ⚠️ AND SETTING THEM AT ALL IS THE POINT, because 3.8 THINKS BY DEFAULT.
 * Measured 2026-11-09: a `workout_generate` call that was never given a
 * `thinkingConfig` still reported 3,156 thinking tokens against 2,892 of
 * output — reasoning was more than half the billed output, uninstructed.
 * Leaving these unset does not mean "no thinking", it means "unbounded
 * thinking, ~120 times per plan". Thinking tokens bill as output.
 *
 * MATCH gets least: choosing one of five candidate foods is discrimination,
 * and it runs ~120 times. ESTIMATE gets more: its numbers go straight into the
 * plan with nothing downstream to check them, and it only runs for foods
 * FatSecret could not price at all.
 */
const MATCH_THINKING_BUDGET = Number(process.env.GEMINI_MATCH_THINKING ?? 512);
const ESTIMATE_THINKING_BUDGET = Number(process.env.GEMINI_ESTIMATE_THINKING ?? 1024);

/**
 * What a call gets when the app asks for no thinking budget of its own.
 *
 * ⚠️ WITHOUT THIS, "NO thinkingConfig" MEANS UNBOUNDED, NOT NONE. 3.8 thinks by
 * default — measured 2026-11-09, a `workout_generate` call carrying no
 * thinking config at all still spent 3,156 thinking tokens against 2,892 of
 * output. Fifteen distinct operations reach this endpoint and exactly one
 * (`diet_generate`) sets a budget, so everything else was running uncapped.
 *
 * A default here rather than a budget at fifteen call sites: one place to
 * change, nothing to forget on the sixteenth, and an app that does set one
 * still wins outright.
 */
const DEFAULT_THINKING_BUDGET = Number(process.env.GEMINI_DEFAULT_THINKING ?? 1024);

/**
 * What a client may ask a generation to spend (M5).
 *
 * ⚠️ `/api/ai/generate` USED TO SPREAD `generationConfig` STRAIGHT THROUGH, so
 * a subscriber chose `candidateCount`, `maxOutputTokens`, `thinkingBudget`,
 * `responseModalities` — anything Gemini accepts. Thinking tokens bill as
 * output, so those three between them set the bill.
 *
 * ⚠️ THE OUTPUT CAP IS THE LEVER, NOT THE THINKING ONE, which is worth knowing
 * before anyone tunes these. At the standard `gemini-3.8-flash` rate of $7.50
 * per million output tokens, 4,096 thinking + 32,768 output is $0.2765 a call
 * — and the output half is 89% of it. Doubling the thinking cap to 8,192 moves
 * the ceiling by 11%. A measured real `diet_generate` costs $0.0701, so this
 * pair is a little under 4x a true call: headroom, not a straitjacket.
 *
 * 32,768 is the largest the client asks for (the diet main draft) and 4,096 is
 * the largest thinking it asks for. Both are env-overridable so a future model
 * needing more is a Railway variable rather than a deploy.
 */
const GEMINI_MAX_OUTPUT_TOKENS = envInt('GEMINI_MAX_OUTPUT_TOKENS', 32768, '[gemini]');
const GEMINI_MAX_THINKING = envInt('GEMINI_MAX_THINKING', 4096, '[gemini]');

/**
 * What ONE attempt is charged at admission, before anyone knows its real cost.
 *
 * ⚠️ IT IS A TRUE UPPER BOUND, WHICH IS WHY CHARS CONVERT AT 1 AND NOT 4.
 * Four characters per token is the realistic ratio and would make this four
 * times smaller — but then the sentence "the reservation covers the worst
 * case" is false for dense Unicode, and the whole burst defence rests on that
 * sentence. Same bound `MAX_PROMPT_CHARS` relies on: tokens per character is
 * at most about 1.
 *
 * ⚠️ ONE ATTEMPT, NOT TWO, EVEN THOUGH THE FALLBACK MAKES TWO POSSIBLE. The
 * attempts are awaited in order and the reservation is not released until the
 * response closes, so during the second attempt the accumulator holds
 * `measured_1 + RESERVE` — exactly right, with the second attempt's unknown
 * cost covered by the reservation still outstanding. Reserving two would halve
 * legitimate concurrency to no purpose.
 *
 * ⚠️ THE IMAGE ALLOWANCE IS A JUDGEMENT AND ITS EXACT VALUE DOES NOT MATTER.
 * Gemini bills an image by tile count, 258 tokens per 768x768 tile: a 12 MP
 * 3:4 photo is ~24 tiles (~6,200 tokens) and a 48 MP original at quality 0.8
 * with no resize — which the Supabase Storage fallback in the photo senders
 * can serve — is ~88 tiles (~22,700). 8,000 sits above the common case and
 * below the extreme. It is only ever a RESERVATION: `logUsage` settles the
 * measured figure, so an under-reserve costs a few seconds of concurrency
 * headroom while a call is in flight and never distorts the monthly total.
 */
const IMAGE_TOKEN_ALLOWANCE = 8000;
const RESERVE_PER_ATTEMPT =
    (MAX_PROMPT_CHARS + MAX_IMAGE_PARTS * IMAGE_TOKEN_ALLOWANCE) / PROMPT_UNIT_DIVISOR
    + GEMINI_MAX_OUTPUT_TOKENS + GEMINI_MAX_THINKING;

/**
 * ⚠️ A BUDGET SMALLER THAN ONE RESERVATION REFUSES EVERY CALL, including the
 * first of the month, and the refusal would look like a quota working rather
 * than a misconfiguration. Anyone lowering AI_LIMIT_MONTHLY_SPEND to throttle
 * a user would hit this long before they reached zero.
 */
if (MONTHLY_UNIT_BUDGET < RESERVE_PER_ATTEMPT) {
    throw new Error(
        `[ratelimit] AI_LIMIT_MONTHLY_SPEND is ${MONTHLY_UNIT_BUDGET} but one attempt reserves `
        + `${Math.round(RESERVE_PER_ATTEMPT)} units, so every call would be refused. Raise it above that.`
    );
}

/** The only two the client asks for, and the only two worth forwarding. */
const ALLOWED_RESPONSE_MIME_TYPES = new Set(['application/json', 'text/plain']);

// Asks Gemini to judge, from the REAL FatSecret candidates for one search,
// which one (if any) is genuinely the same food as the ingredient - this is
// the primary match-acceptance check, replacing word-overlap guessing with
// the same semantic judgment the AI that wrote the ingredient already has.
// One call covers all candidates at once (not one call per candidate) so this
// costs a single round-trip per ingredient, not up to five.
//
// Returns the chosen candidate object, or `null` when the AI says none of the
// candidates are correct (a real "no match" - same as an empty search to the
// caller, which falls through to the foodSimplified retry and eventually
// ingredient repair). Throws on any call/parse failure (network error, missing
// API key, unparseable response) - searchFoodItem catches that and falls back
// to pickFoodMatchByWords, so a transient AI outage degrades gracefully
// instead of breaking nutrition lookup entirely.
async function pickBestFoodMatchWithAI(searchExpression, foodCore, candidates) {
    const matchStartedAt = Date.now();
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) throw new Error('GEMINI_API_KEY not configured');

    const listing = candidates.map((f, i) =>
        `${i + 1}. "${f.food_name}" (${f.food_type})${f.food_description ? ` - ${f.food_description}` : ''}`
    ).join('\n');

    const prompt = `You are verifying a nutrition-database search result before it gets used to calculate calories/macros.
Ingredient: "${searchExpression}"${foodCore ? ` (core food identity: "${foodCore}")` : ''}

Candidate database entries:
${listing}

Which numbered entry, if any, is genuinely the SAME food as the ingredient? Reject an entry only if it is a categorically different product derived FROM the ingredient (e.g. the ingredient is a whole fruit/nut/vegetable but the candidate is its oil, juice, sauce, syrup, extract, or paste), a prepared dish, or an unrelated branded product that merely shares words with the ingredient. Do NOT reject a candidate just because its name includes a qualifier describing that same food's own normal composition or how it's typically sold (e.g. "whey protein powder" IS whey protein - protein supplements are normally sold as powder; "whole milk greek yogurt" IS greek yogurt - milk-fat content is a descriptor, not a different product).

Respond with ONLY the number of the correct entry, or 0 if none are correct. No explanation, no other text.`;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 15000);
    try {
        const response = await fetch(
            `https://generativelanguage.googleapis.com/v1beta/models/${MATCH_MODEL}:generateContent?key=${apiKey}`,
            {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    contents: [{ parts: [{ text: prompt }] }],
                    generationConfig: {
                        temperature: 0,
                        thinkingConfig: { thinkingBudget: MATCH_THINKING_BUDGET, includeThoughts: false },
                    },
                }),
                signal: controller.signal,
            }
        );
        if (!response.ok) throw new Error(`Gemini verification call returned ${response.status}`);
        const data = await response.json();
        logUsage('match', MATCH_MODEL, data, Date.now() - matchStartedAt);
        const text = data.candidates?.[0]?.content?.parts?.[0]?.text?.trim() || '';
        const match = text.match(/\d+/);
        if (!match) throw new Error(`Gemini verification returned unparseable response: "${text}"`);
        const choice = parseInt(match[0], 10);
        if (choice === 0) return null;
        if (choice >= 1 && choice <= candidates.length) return candidates[choice - 1];
        throw new Error(`Gemini verification returned out-of-range choice: ${choice}`);
    } finally {
        clearTimeout(timeoutId);
    }
}

// Last-resort macro source for an ingredient that genuinely has no FatSecret
// match at all (not even after the caller has already retried with a
// different, more common ingredient) - asks Gemini for the ingredient's real
// per-serving macros instead of failing the whole plan over one obscure food.
//
// Only asks the AI for protein/carbs/fat, never calories directly - calories
// is derived here from those three (4/4/9) so it can't disagree with them,
// the same "let the AI classify, let code compute" principle already used for
// FatSecret's own density backstop below. Two independent plausibility gates
// before this is trusted: an absolute per-macro ceiling (works for any unit),
// plus the existing energy-density ceiling when the ingredient's unit
// converts cleanly to grams (g/kg/oz/ml) - ambiguous units like "scoop" skip
// that second gate rather than guess a gram weight for it, same fallback
// `isPlausible` already uses when it has no reference grams.
async function estimateIngredientMacrosWithAI(ingredientStr, foodCore) {
    const estimateStartedAt = Date.now();
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) throw new Error('GEMINI_API_KEY not configured');

    const prompt = `You are a nutrition database, answering with the real-world macronutrient content of a food ingredient exactly as commonly known - not a rough guess.

Ingredient, with its stated quantity: "${ingredientStr}"${foodCore ? ` (food identity: "${foodCore}")` : ''}

Using standard nutrition data for this food, respond with ONLY the protein, carbohydrate, and fat content in grams for exactly the quantity stated - no other text, strict JSON, no markdown fences:
{"protein": 0, "carbs": 0, "fat": 0}`;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 15000);
    let text;
    try {
        const response = await fetch(
            `https://generativelanguage.googleapis.com/v1beta/models/${ESTIMATE_MODEL}:generateContent?key=${apiKey}`,
            {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    contents: [{ parts: [{ text: prompt }] }],
                    generationConfig: {
                        temperature: 0,
                        thinkingConfig: { thinkingBudget: ESTIMATE_THINKING_BUDGET, includeThoughts: false },
                    },
                }),
                signal: controller.signal,
            }
        );
        if (!response.ok) throw new Error(`Gemini estimate call returned ${response.status}`);
        const data = await response.json();
        logUsage('estimate', ESTIMATE_MODEL, data, Date.now() - estimateStartedAt);
        text = data.candidates?.[0]?.content?.parts?.[0]?.text?.trim() || '';
    } finally {
        clearTimeout(timeoutId);
    }

    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) throw new Error(`Gemini estimate returned unparseable response: "${text}"`);
    const parsed = JSON.parse(jsonMatch[0]);
    const protein = Number(parsed.protein);
    const carbs = Number(parsed.carbs);
    const fat = Number(parsed.fat);

    // No single recipe ingredient realistically supplies more than this of any
    // one macro - catches a wildly hallucinated figure regardless of unit.
    const MAX_MACRO_GRAMS = 500;
    if (![protein, carbs, fat].every(n => Number.isFinite(n) && n >= 0 && n <= MAX_MACRO_GRAMS)) {
        return null;
    }
    const calories = protein * 4 + carbs * 4 + fat * 9;

    const parsedIng = parseIngredient(ingredientStr);
    const grams = toGrams(parsedIng.quantity, parsedIng.unit);
    if (!isPlausible({ calories }, grams)) return null;

    return {
        ingredient: ingredientStr,
        food_name: `${parsedIng.food || ingredientStr} (AI estimate - not in nutrition database)`,
        calories: Math.round(calories),
        protein: Math.round(protein),
        carbs: Math.round(carbs),
        fat: Math.round(fat),
        referenceServingGrams: null,
        referenceServingUnit: null,
        gramsPerOriginalUnit: null,
    };
}

/**
 * FatSecret's failures arrive as HTTP 200 with an `error` envelope.
 *
 * ⚠️ THIS COST A FULL EVENING TO FIND, AND IT WAS INVISIBLE THE WHOLE TIME.
 * `{"error":{"code":21,"message":"Invalid IP address detected"}}` comes back
 * with a 200, so `response.ok` is TRUE, the `!ok` guard never fires, and the
 * parse below finds no `foods.food` key and concludes "no results for this
 * ingredient". The proxy could not tell a total outage from a food FatSecret
 * genuinely does not stock.
 *
 * What the user saw was the app blaming their ingredients — "couldn't verify
 * 220 g chicken breast" — after an eight-minute wait, while the real answer
 * (an IP allowlist rejecting every call for 46 hours) was in a response body
 * nobody read.
 *
 * Codes worth recognising on sight: 21 = calling IP not on the allowlist,
 * 12 = missing/invalid oauth token, 13 = invalid signature, 14 = expired.
 *
 * Returns the error so callers can bail, and logs at ERROR — this is never
 * normal, and it must never look like an empty result set again.
 */
function fatSecretError(data, context) {
    const err = data && data.error;
    if (!err) return null;
    console.error(`[FatSecret] ${context} FAILED — code ${err.code}: ${err.message}`);
    return err;
}

const FATSECRET_URL = 'https://platform.fatsecret.com/rest/server.api';

/**
 * FatSecret error codes worth a SECOND ROLL OF THE DICE.
 *
 * 21 is "Invalid IP address detected". It reads like a permanent configuration
 * error and is not one here: this service egresses through a POOL of Railway
 * static IPs, one picked per connection, and an allowlist can be live for some
 * of them and not others. Observed exactly that — two of three accepted while
 * `152.55.184.241` was refused for hours, so roughly a third of all lookups
 * failed on nothing but which address they happened to leave from.
 *
 * ⚠️ ONLY codes whose outcome can CHANGE between identical requests belong
 * here. A bad food id or a malformed query will fail the same way forever, and
 * retrying those just multiplies latency by three on the calls least likely to
 * benefit.
 */
const RETRYABLE_FATSECRET_CODES = new Set([21]);
const FATSECRET_RETRIES = 2;

/**
 * One FatSecret POST, retried when FATSECRET refuses rather than when HTTP does.
 *
 * ⚠️ THE EXISTING fetchWithRetry CANNOT DO THIS, and that is the whole point of
 * this wrapper. It retries on `429` or `5xx` — but a refusal arrives as a
 * perfectly good **HTTP 200** carrying an error envelope, so `response.ok` is
 * true and it returns first time, every time. The failure this exists for is
 * invisible at the layer that decides to retry.
 *
 * ⚠️ `Connection: close` IS THE LOAD-BEARING HEADER, not politeness. Node keeps
 * sockets alive and reuses them, and a retry down the SAME socket leaves from
 * the SAME egress IP — which is the one that just refused us. Reusing the
 * connection would make this wrapper pure latency. Asking the server to close
 * means the next attempt dials again and gets another draw from the pool.
 *
 * ⚠️ AND IT IS A DRAW, NOT A ROTATION. Railway assigns an address per
 * connection at random; a retry can land on the bad one again. With three IPs
 * and one refusing, a single attempt fails ~33% of the time, two ~11%, three
 * ~4%. This makes the failure rare, never impossible — callers must still cope
 * with a null.
 *
 * The rescue log below is the only honest evidence that any of this works: if
 * `Connection: close` is ignored and the socket is reused, every retry fails
 * identically and NO rescue line is ever printed. Absence of that line after a
 * spell of code 21s means this approach needs replacing (raw node:https with
 * `agent: false`), not that the outage is over.
 */
async function fatSecretPost(params, token, context) {
    let last = { ok: false, status: 0, data: null };

    for (let attempt = 0; attempt <= FATSECRET_RETRIES; attempt++) {
        const response = await fetchWithRetry(FATSECRET_URL, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/x-www-form-urlencoded',
                'Connection': 'close',
            },
            body: new URLSearchParams(params),
        });

        if (!response.ok) return { ok: false, status: response.status, data: null };

        const data = await response.json().catch(() => null);
        const code = Number(data?.error?.code);
        const retryable = Number.isFinite(code) && RETRYABLE_FATSECRET_CODES.has(code);

        if (!retryable) {
            if (attempt > 0 && !data?.error) {
                console.warn(
                    `[FatSecret] ${context} — retry ${attempt}/${FATSECRET_RETRIES} SUCCEEDED. ` +
                    `The earlier attempt(s) left from a refused egress IP; this one did not.`
                );
            }
            return { ok: true, status: response.status, data };
        }

        last = { ok: true, status: response.status, data };
        if (attempt < FATSECRET_RETRIES) {
            console.warn(
                `[FatSecret] ${context} refused with code ${code} on attempt ${attempt + 1}/${FATSECRET_RETRIES + 1} ` +
                `— redialling on a fresh connection for a different egress IP.`
            );
        }
    }

    // Every attempt refused. The caller reports it through fatSecretError as before.
    return last;
}

async function searchFoodItem(searchExpression, token, foodCore) {
    const { ok, status, data: searchData } = await fatSecretPost({
        method: 'foods.search',
        search_expression: searchExpression,
        format: 'json',
        max_results: '5'
    }, token, `foods.search "${searchExpression}"`);

    if (!ok) {
        console.warn(`[Free Search] FatSecret search failed for "${searchExpression}":`, status);
        // A 5xx is the service, not the food. See noteServiceFailure.
        noteServiceFailure(`HTTP ${status}`, 'non-2xx from FatSecret');
        return null;
    }
    // Before reading results: a rejection arrives here as a 200 with an error
    // envelope, and would otherwise parse as "no matches". See fatSecretError.
    //
    // ⚠️ RECORDED AS A SERVICE FAILURE, not just logged. An error envelope is
    // FatSecret declining to answer — an allowlist rejection, a bad token, a
    // quota — and is categorically different from a search that ran and matched
    // nothing (which returns 200 with an empty `foods.food`). Both still return
    // null to the caller, because the caller's next move is the same either way;
    // what changes is that the outage is now visible in /health and in the log.
    const searchErr = fatSecretError(searchData, `foods.search "${searchExpression}"`);
    if (searchErr) {
        noteServiceFailure(searchErr.code, searchErr.message);
        return null;
    }
    const rawResults = searchData.foods?.food;
    const results = Array.isArray(rawResults) ? rawResults : (rawResults ? [rawResults] : []);
    const usable = results.filter(f => f && f.food_id);
    if (usable.length === 0) return null;

    try {
        return await pickBestFoodMatchWithAI(searchExpression, foodCore, usable);
    } catch (err) {
        console.warn(`[Free Search] AI match verification failed for "${searchExpression}", falling back to word-based matching:`, err.message);
    }

    return pickFoodMatchByWords(searchExpression, foodCore, usable);
}

/**
 * The deep probe's last answer, so polling cannot burn FatSecret quota.
 *
 * A real lookup costs an API call against a quota the whole app shares, and
 * /health is unauthenticated — without this, anything that polls it every few
 * seconds spends the allowance the meal generator needs.
 */
let lastDeepProbe = null;
const DEEP_PROBE_TTL_MS = 60_000;

/**
 * Health check. `?deep=1` makes it mean something.
 *
 * ⚠️ THE SHALLOW ANSWER IS NEARLY USELESS AND HAS ALREADY MISLED US. It reports
 * `hasClientId: true` and `status: "ok"` when the credentials merely EXIST —
 * which is exactly what it said for 46 hours while FatSecret rejected every
 * single call on an IP allowlist. The one field that hinted at the truth was
 * `foodCache`, sitting at zero, and only because nothing had ever succeeded.
 *
 * The deep probe does one real `foods.search` and reports what came back, so
 * "is the nutrition service actually working" becomes a question with an
 * answer rather than an inference.
 */
app.get('/health', wrap(async (req, res) => {
    /**
     * ⚠️ THE SHALLOW ANSWER NOW REFLECTS REAL TRAFFIC, which is the whole point.
     * It used to be hardcoded "ok" and said so for 46 hours through one outage
     * and 43 through another, because it only ever checked that credentials
     * EXISTED. It now reports `degraded` whenever a real lookup was refused in
     * the last ten minutes — so a plain uptime monitor watching this endpoint
     * catches an outage without needing ?deep=1 or a FatSecret round trip.
     *
     * The deep probe is still the stronger signal: this can only report failures
     * that TRAFFIC discovered, so an idle server with a broken allowlist still
     * looks fine here until someone generates a plan. Use ?deep=1 to ask
     * directly; use this to notice.
     */
    const degraded = serviceIsDegraded();
    const body = {
        status: degraded ? "degraded" : "ok",
        uptime: process.uptime(),
        nativeNlpMode: USE_NATIVE_NLP,
        config: {
            hasClientId: !!process.env.FATSECRET_CLIENT_ID,
            hasClientSecret: !!process.env.FATSECRET_CLIENT_SECRET
        },
        // Null when nothing has been refused recently. `count` is for the life of
        // the process, so it keeps counting across episodes.
        fatSecretLastFailure: lastServiceFailure
            ? { ...lastServiceFailure, ageMs: Date.now() - lastServiceFailure.at, count: serviceFailureCount }
            : null,
        foodCache: {
            searchEntries: foodSearchCache.size,
            detailEntries: foodDetailCache.size
        }
    };

    if (req.query.deep !== '1') return res.json(body);

    // ⚠️ `&& !degraded`, on both deep paths. The probe is a SAMPLE and this one is
    // up to DEEP_PROBE_TTL_MS old — so a probe that passed minutes ago must not
    // overwrite a refusal that real traffic hit since. Either signal saying
    // "degraded" means degraded; only both agreeing means ok.
    if (lastDeepProbe && Date.now() - lastDeepProbe.at < DEEP_PROBE_TTL_MS) {
        return res.json({
            ...body,
            status: lastDeepProbe.result.ok && !degraded ? 'ok' : 'degraded',
            fatSecret: { ...lastDeepProbe.result, cached: true },
        });
    }

    let result;
    try {
        const token = await getFatSecretToken();
        const started = Date.now();
        const probe = await fetch('https://platform.fatsecret.com/rest/server.api', {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                method: 'foods.search',
                // A food FatSecret certainly stocks, so an empty result set can
                // only mean something is wrong rather than an obscure query.
                search_expression: 'chicken breast',
                format: 'json',
                max_results: '1'
            })
        });
        const data = await probe.json().catch(() => ({}));
        const elapsedMs = Date.now() - started;
        const err = fatSecretError(data, 'health probe');
        // ⚠️ RECORDED, not just reported. A probe that FatSecret refuses is
        // evidence of the same outage a user's lookup would hit — and without
        // this the two halves of /health contradict each other: the deep answer
        // says the probe failed while the shallow one says "ok", because the
        // traffic-based window quietly expired. Observed live: a refusal at
        // 19:09 and `status: "ok"` at 19:14, five minutes apart.
        if (err) noteServiceFailure(err.code, err.message);
        result = err
            ? { ok: false, code: err.code, message: err.message, elapsedMs }
            : { ok: !!data?.foods?.food, matched: data?.foods?.food?.food_name ?? null, elapsedMs };
    } catch (e) {
        // A probe that could not even be attempted (token fetch, DNS, timeout)
        // is also the service being unreachable, not a quiet nothing.
        noteServiceFailure('probe-exception', e.message || String(e));
        result = { ok: false, message: e.message || String(e) };
    }

    lastDeepProbe = { at: Date.now(), result };
    // A fresh probe can clear its own doubt but not traffic's — see above. If the
    // probe passes while lookups are being refused, something is wrong that a
    // single "chicken breast" query does not reach, and "ok" would be a lie.
    return res.json({ ...body, status: result.ok && !degraded ? 'ok' : 'degraded', fatSecret: result });
}));

// ---------------------------------------------------------------------------
// Gemini generateContent proxy
// ---------------------------------------------------------------------------
// Exists so the app never has to hold a Gemini API key. Previously the client
// called generativelanguage.googleapis.com directly using
// EXPO_PUBLIC_GEMINI_API_KEY — and any EXPO_PUBLIC_* value is compiled into the
// shipped app bundle, so that key was extractable from any installed copy of
// the app and chargeable to us. The key now lives only here, server-side.
//
// Deliberately a thin pass-through: the caller still owns the prompt,
// generationConfig and (optionally) the model, so adding/'changing a prompt
// never needs a proxy change. Only the credential moves.
/* ⚠️ `express.json` IS NOT WRAPPED, and must not be. `wrap` exists for
   middleware that returns a PROMISE; body-parser reports through `next(err)`
   already, which is what carries its 413 and its malformed-JSON 400 to the
   error handler. Wrapping it would add a layer that never fires.

   ⚠️ IT SITS AFTER BOTH GUARDS AND BEFORE BOTH CHECKS. `validateAiRequest`
   and `rateLimitAi` both need `req.body` — operation, contents, initiated,
   workoutId — so the parser has to precede them; nothing above it does, since
   H1. The order of the two after it is H3's: shape first, then ration. */
app.post('/api/ai/generate', wrap(requireUser), wrap(requireSubscription), express.json({ limit: GENERATE_BODY_LIMIT_BYTES }), validateAiRequest, wrap(rateLimitAi), wrap(async (req, res) => {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
        return res.status(500).json({ error: { message: 'GEMINI_API_KEY not configured on the proxy server.' } });
    }

    /* ⚠️ `contents` IS RE-CHECKED BELOW AND THAT IS NOT DEAD CODE BY ACCIDENT.
       `validateAiRequest` has already refused every shape this route rejects,
       so the check cannot fire through the router — it stays because it is the
       handler's own precondition and the next caller may not come through the
       same middleware chain. */
    const { contents, generationConfig, model } = req.body || {};
    /* Only for the usage line — see logUsage on why this is a hint, not a fact. */
    const operationLabel = typeof req.body?.operation === 'string' ? req.body.operation : null;
    if (!Array.isArray(contents) || contents.length === 0) {
        return res.status(400).json({ error: { message: 'Request must include a non-empty "contents" array.' } });
    }

    // Allow the caller to pick a model, but only from a known-good set — an
    // unvalidated passthrough would let anyone who can reach this proxy bill us
    // for an arbitrarily expensive model.
    const ALLOWED_MODELS = new Set(['gemini-3.8-flash', 'gemini-3.6-flash', 'gemini-3.1-flash-lite', 'gemini-3.5-flash', 'gemini-3.5-flash-lite']);
    const chosenModel = model && ALLOWED_MODELS.has(model) ? model : GEMINI_MODEL;

    /**
     * The model to retry on when the chosen one cannot serve the request.
     *
     * ⚠️ ONLY FOR FAILURES THAT ARE ABOUT THE MODEL, NOT THE REQUEST. 404 means
     * the model does not exist for this project — which is also the honest
     * safety net for a name nobody has verified against the live API. 429 means
     * this model's quota is spent, and a newly-introduced model on promotional
     * pricing is exactly where a tighter quota shows up first. Both are fast and
     * definite.
     *
     * ⚠️ NOT 400, AND NOT A TIMEOUT. A 400 is a malformed request and the
     * fallback would fail identically, having spent the round trip. A timeout is
     * worse: the app owns a 180s deadline and has already aborted by then, so a
     * retry answers a socket nobody is holding — see the CLIENT ABORTED branch
     * above. 5xx is left alone too, because `fetchGeminiWithRetry` in the app
     * already retries those inside its own budget; retrying here as well would
     * compound into two nested retry loops.
     */
    const FALLBACK_MODEL = 'gemini-3.6-flash';
    const MODEL_FALLBACK_STATUSES = new Set([404, 429]);

    /**
     * Timing, because "the AI took too long" is otherwise unanswerable.
     *
     * The app aborts a generation at 180s and shows "Our AI engine took too
     * long to respond" — but the app owns that deadline, so from here the
     * request simply stops existing. Nothing on either side records how long it
     * had actually been running, which model it was, or how big the ask was.
     *
     * ⚠️ THIS IS THE ONLY PLACE THAT CAN SEE IT FOR EXISTING INSTALLS. Builds
     * shipped before expo-updates cannot be fixed or instrumented remotely, and
     * the tester who reported the timeout is on one. The proxy sees every
     * request from every build.
     *
     * `promptChars` is what distinguishes the calls: the main draft's prompt is
     * far larger than a repair round's or the instructions pass, and the app
     * sends no label.
     */
    const startedAt = Date.now();
    const promptChars = JSON.stringify(contents).length;

    /**
     * The client giving up is the event worth catching, and it arrives as a
     * closed socket rather than an error. Registered BEFORE the await, or the
     * abort can land while we are still setting up and go unlogged.
     *
     * ⚠️ `res.on`, NOT `req.on`, AND THIS LINE WAS FALSE ON EVERY GENERATION
     * UNTIL IT WAS CHANGED. The REQUEST stream closes as soon as its body has
     * been consumed — which `express.json` does before this handler runs — so
     * `req.on('close')` fired at 0ms on every call, `res.writableEnded` was
     * naturally still false that early, and the log claimed "CLIENT ABORTED …
     * This is the app's 180s deadline firing" about requests that went on to
     * answer 200 a minute later. Measured, same request, both handlers
     * attached:
     *
     *     connected, answers at 1200ms:  req fired at 0ms,  res never fired
     *     client aborts at 400ms:        req fired at 0ms,  res fired at 405ms
     *
     * The RESPONSE stream closes when the socket does, which is the thing we
     * mean. `!res.writableEnded` is what separates an abort from a normal
     * finish, since `close` fires for both — on a completed request it lands
     * after `finish`, with `writableEnded` true.
     *
     * This is the same trap the nutrition loops hit (see `aborted()` there),
     * and it predates that work: anyone reading this log in production was
     * being sent after a timeout that had not happened.
     */
    res.on('close', () => {
        if (!res.writableEnded) {
            console.warn(
                `[AI Proxy] CLIENT ABORTED after ${Date.now() - startedAt}ms — ` +
                `model ${chosenModel}, prompt ${promptChars} chars. ` +
                `This is the app's 180s deadline firing.`
            );
        }
    });

    /**
     * One attempt against one model. Returns the status, body and timing so the
     * caller can decide whether to try the fallback.
     *
     * No timeout here on purpose: the client already owns the deadline via its
     * own AbortController, and aborting client-side tears down this request too.
     * A second, shorter timeout here would just truncate long (but healthy)
     * generations — a flash draft legitimately runs ~70s.
     */
    /* Whitelisted, clamped and bounded by `buildGenerationConfig` — see it for
       why this is built from scratch rather than spread. Built once, outside
       the retry, so the fallback attempt sends exactly what the primary did. */
    const { config: effectiveConfig, warnings: configWarnings } = buildGenerationConfig(generationConfig);
    /* One line per rejected key, naming the operation. Silent for every shape
       the real client sends, so anything here is either abuse or a client
       change nobody told the proxy about — both worth seeing in the log. */
    for (const w of configWarnings) {
        console.warn(`[gemini] ${req.userId} ${operationLabel ?? req.path} — ${w}`);
    }

    const callModel = async (modelName) => {
        const attemptStart = Date.now();
        const geminiResponse = await fetch(
            `https://generativelanguage.googleapis.com/v1beta/models/${modelName}:generateContent?key=${apiKey}`,
            {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ contents, generationConfig: effectiveConfig }),
            }
        );
        const data = await geminiResponse.json().catch(() => ({}));
        const elapsedMs = Date.now() - attemptStart;
        const replyChars = (data?.candidates?.[0]?.content?.parts?.[0]?.text || '').length;

        // One line per call, always — a slow SUCCESS is the number that says
        // whether 180s is a sane ceiling or a coin toss, and it never shows up
        // if only failures are logged. Note the app retries 5xx up to twice
        // INSIDE its single 180s budget, so several of these lines can belong
        // to one user-visible generation.
        console.log(
            `[AI Proxy] ${modelName} ${geminiResponse.status} in ${elapsedMs}ms — ` +
            `prompt ${promptChars} chars, reply ${replyChars} chars`
        );
        if (geminiResponse.ok) logUsage(operationLabel || 'unlabelled', modelName, data, elapsedMs);
        return { status: geminiResponse.status, ok: geminiResponse.ok, data };
    };

    try {
        let attempt = await callModel(chosenModel);

        if (!attempt.ok && MODEL_FALLBACK_STATUSES.has(attempt.status) && chosenModel !== FALLBACK_MODEL) {
            /* ⚠️ LOUD, BECAUSE A SILENT FALLBACK IS A SILENT DOWNGRADE. If the
               primary model is unavailable or out of quota every single call,
               everything keeps working and nothing says the cheaper model is
               never actually being used. Grep this line to find out. */
            console.warn(
                `[AI Proxy] ${chosenModel} returned ${attempt.status} — falling back to ${FALLBACK_MODEL}`
            );
            attempt = await callModel(FALLBACK_MODEL);
        }

        if (!attempt.ok) {
            console.warn(`[AI Proxy] Gemini returned ${attempt.status} after ${Date.now() - startedAt}ms`);
        }
        // Mirror Gemini's status so the app's existing handling (429 quota
        // messaging, 5xx retry in fetchGeminiWithRetry) keeps working unchanged.
        return res.status(attempt.status).json(attempt.data);
    } catch (err) {
        console.error(`[AI Proxy] Request failed after ${Date.now() - startedAt}ms:`, err.message || err);
        return res.status(502).json({ error: { message: `Could not reach the AI service: ${err.message || err}` } });
    }
}));

/**
 * What a nutrition request may ask for, and what it costs — decided ONCE,
 * before the limiter, for both routes.
 *
 * ⚠️ IT RUNS BEFORE `rateLimitFixed`, AND THE ORDER IS THE POINT. The first
 * shape of this fix put the caps in the handlers and the metering in the
 * limiter, which runs first — so a 13,000-ingredient body would have spent
 * 13,000 tokens from a 1,500/hour budget and THEN been refused as malformed.
 * One bad request would have emptied a subscriber's hour at no cost to
 * whoever sent it: a denial of service built out of a rate limiter. A request
 * that is going to be rejected must be rejected before it is charged.
 *
 * ⚠️ IT ALSO PAIRS AND CLEANS, which is not scope creep — both handlers
 * carried identical copies of these type checks AND of the pairing below, and
 * the cost has to be computed from the SAME filtering the loop will do or the
 * charge and the work drift apart. One filter, used by both.
 *
 * ⚠️ THE COST IS THE NON-BLANK COUNT. Both loops skip blank strings, so sixty
 * blanks do no upstream work and are charged nothing. A cost of 0 passes the
 * limiter deliberately — see takeAiToken.
 */
const MAX_INGREDIENTS = 60;
const MAX_INGREDIENT_CHARS = 200;

const validateIngredients = (req, res, next) => {
    const { ingredients, foodCores } = req.body || {};

    /* ⚠️ THE ELEMENTS, NOT JUST THE ARRAY. `Array.isArray` alone let
       `[123]` through to `(123 || '').trim()` below — a number is truthy, so
       the `|| ''` guard does not catch it — and that TypeError inside an async
       handler took the process down. `foodCores` is validated too because it
       is indexed in parallel with `ingredients` a few lines on. */
    if (!Array.isArray(ingredients) || !ingredients.every(i => typeof i === 'string')) {
        return res.status(400).json({ error: "ingredients must be an array of strings" });
    }
    if (foodCores !== undefined
        && (!Array.isArray(foodCores) || !foodCores.every(c => c == null || typeof c === 'string'))) {
        return res.status(400).json({ error: "foodCores must be an array of strings or nulls" });
    }

    /**
     * ⚠️ SIXTY IS A JUDGEMENT, NOT A DERIVED NUMBER, and whoever wants to
     * raise it should know that. There is no rule in the generation prompt
     * capping ingredients per meal; what the prompt actually discusses is
     * meals with "1-2 ingredients" and "3+ ingredients", and `/analyze` is
     * called once per MEAL (DietSetupFlow passes `meal.ingredients`). So the
     * observed shape is single digits and this is roughly ten times it.
     */
    if (ingredients.length > MAX_INGREDIENTS) {
        return res.status(400).json({ error: `ingredients must contain at most ${MAX_INGREDIENTS} entries` });
    }
    /* These strings become FatSecret search expressions AND get embedded in a
       model prompt. Nothing a meal contains is this long; something that is,
       is either a mistake or an attempt to use the prompt as a channel. */
    if (ingredients.some(i => i.length > MAX_INGREDIENT_CHARS)) {
        return res.status(400).json({ error: `each ingredient must be at most ${MAX_INGREDIENT_CHARS} characters` });
    }
    /* The two arrays are read by a shared index, so entries past the end of
       `ingredients` can never be reached — a longer one is always a mistake,
       and saying so beats silently ignoring the tail. */
    if (Array.isArray(foodCores) && foodCores.length > ingredients.length) {
        return res.status(400).json({ error: "foodCores must not be longer than ingredients" });
    }

    // Pair each ingredient with its food_core (if any) before filtering out blank
    // ingredients - filtering the two arrays independently risks shifting them out
    // of index alignment.
    const paired = ingredients
        .map((ing, i) => ({
            ingredient: (ing || '').trim(),
            foodCore: Array.isArray(foodCores) ? (foodCores[i] || null) : null
        }))
        .filter(p => p.ingredient.length > 0);
    const cleanIngredients = paired.map(p => p.ingredient);
    const cleanFoodCores = paired.map(p => p.foodCore);

    req.nutrition = { paired, cleanIngredients, cleanFoodCores };
    return next();
};

/** The ingredient cost of a validated request — see AI_LIMITS.nutrition. */
const ingredientCost = (req) => req.nutrition?.cleanIngredients.length ?? 0;

/**
 * Timing for the nutrition routes.
 *
 * Middleware rather than a line at each `res.json`, because between them these
 * two handlers return from seven different places — early validation exits, the
 * native-NLP branch, the free-search branch, the error catch — and one of them
 * would inevitably be missed, which is precisely how a slow path stays
 * invisible. `finish` fires on every one of them, including any added later.
 *
 * Nutrition verification is a large and completely unmeasured share of the
 * ~10-minute meal generation: the AI calls have a 180s ceiling each and now log
 * their duration, but this stage had no number attached to it at all.
 *
 * Registered BEFORE the handlers so it wraps them. The count is what makes a
 * slow line interpretable, since 40 ingredients legitimately takes longer
 * than 6.
 *
 * ⚠️ THE COUNT IS READ IN THE CALLBACKS, NOT HERE, and that is load-bearing
 * since M4. This is an `app.use`, so it runs before the route's own chain —
 * and the parser now lives INSIDE that chain, after `requireUser`. Read at
 * entry, `req.body` is undefined and every line in this log would have said
 * "0 ingredient(s)" for ever. By `finish` the body has been parsed if it was
 * ever going to be.
 *
 * ⚠️ SO "0 ingredient(s)" NO LONGER MEANS "AN EMPTY ARRAY WAS SENT". It also
 * covers a 401, a 402 and a 413 — every case where the body was never parsed
 * at all. Read the status on the same line before drawing a conclusion from
 * the count. The comment this replaced promised the opposite, which is how
 * this dependency went unnoticed.
 */
app.use(['/api/nutrition/analyze', '/api/nutrition/estimate'], (req, res, next) => {
    const startedAt = Date.now();
    const count = () => (Array.isArray(req.body && req.body.ingredients) ? req.body.ingredients.length : 0);

    res.on('finish', () => {
        console.log(`[Nutrition] ${req.path} ${res.statusCode} in ${Date.now() - startedAt}ms — ${count()} ingredient(s)`);
    });
    // The app gives up at 180s; from here that is only ever a closed socket.
    res.on('close', () => {
        if (!res.writableEnded) {
            console.warn(`[Nutrition] CLIENT ABORTED ${req.path} after ${Date.now() - startedAt}ms — ${count()} ingredient(s)`);
        }
    });
    next();
});

// Nutrition Analysis Endpoint
/* 100kb, not 25mb: these carry ingredient NAME lists. A generation's ~115
   match rows arrive across about 25 requests, so a handful of short strings
   each — two orders of magnitude of headroom, and no reason for this route to
   be able to buffer what the photo route can.

   ⚠️ IT BOUNDS BYTES AND NOT MUCH ELSE. Do not read a tight body limit as a
   bound on the WORK. 100 KiB of legal JSON holds about 34,000 empty strings,
   12,800 five-character ones or 1,600 sixty-character ones — measured, and a
   13,162-element body was accepted here and answered 200. Each unresolved
   ingredient costs up to three FatSecret searches plus a Gemini call plus a
   food.get, and `rateLimitFixed` counts REQUESTS, not ingredients. So this
   limiter is sized for a meal and this parser permits a dictionary, which is
   H3 and is NOT fixed by this number. The cap that matters is on the array
   length, in the handler, and it is still missing. */
app.post('/api/nutrition/analyze', wrap(requireUser), wrap(requireSubscription), express.json({ limit: '100kb' }), validateIngredients, wrap(rateLimitFixed('nutrition', ingredientCost)), wrap(async (req, res) => {
    /* Validated, capped, paired and costed by `validateIngredients` before the
       limiter ran — see it for why that order matters. */
    const { cleanIngredients, cleanFoodCores } = req.nutrition;

    /**
     * Has the caller gone? Checked where it can save an upstream call.
     *
     * ⚠️ NOT `req.destroyed`. That is what this was, and it shipped broken for
     * one commit: `req.destroyed` goes true as soon as the request BODY has
     * been fully consumed, which `express.json` does before the handler ever
     * runs. It says nothing about the client. Measured on node v24.15.0, one
     * connected curl that waits for its answer:
     *
     *     t=0     req.destroyed=false  res.destroyed=false  closeFlag=false
     *     t=150   req.destroyed=TRUE   res.destroyed=false  closeFlag=false
     *     t=1150  req.destroyed=TRUE   res.destroyed=false  closeFlag=false
     *
     * and the same client aborting at 0.4s:
     *
     *     t=1150  req.destroyed=TRUE   res.destroyed=TRUE   closeFlag=TRUE
     *
     * So every request with two or more ingredients stopped after the first
     * and never answered — the loop returned without writing, and the caller
     * hung until its own 180s timeout.
     *
     * ⚠️ A LATCHED FLAG, NOT `res.destroyed`, THOUGH BOTH WORK. The table
     * above shows `res.destroyed` and `req.socket.destroyed` are both correct
     * signals. This uses the close event instead for one reason: the nutrition
     * logger a few hundred lines up decides CLIENT ABORTED with exactly this
     * test — `res.on('close')` with `!res.writableEnded`. Sharing the idiom
     * means the log line and the loop cannot disagree about what an abort is.
     * Picking a second `.destroyed` property would also be the same bet that
     * just lost: trusting a property name to mean what it sounds like.
     *
     * `!res.writableEnded` is what separates an abort from a normal finish —
     * `close` fires for both, and nothing has been written while the loop runs.
     */
    let clientGone = false;
    res.on('close', () => { if (!res.writableEnded) clientGone = true; });
    const aborted = () => clientGone;

    if (cleanIngredients.length === 0) {
        return res.json({ calories: 0, protein: 0, carbs: 0, fat: 0 });
    }

    try {
        const token = await getFatSecretToken();

        // -------------------------------------------------------------
        // OPTION A: Native NLP Mode (Requires Paid $250/mo Add-On)
        // -------------------------------------------------------------
        if (USE_NATIVE_NLP) {
            const userInput = cleanIngredients.join(', ');
            console.log(`[Native NLP] Sending request to FatSecret for ingredients: "${userInput}"`);

            const response = await fetch('https://platform.fatsecret.com/rest/natural-language-processing/v1', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    user_input: userInput,
                    include_food_data: true,
                    region: 'US',
                    language: 'en'
                })
            });

            if (!response.ok) {
                const errText = await response.text();
                console.warn(`[Native NLP] FatSecret API responded with status ${response.status}: ${errText}`);
                return res.status(response.status).json({ error: `FatSecret Native NLP API error: ${errText}` });
            }

            const data = await response.json();
            console.log("[Native NLP] Response:", JSON.stringify(data, null, 2));

            let totalCalories = 0;
            let totalProtein = 0;
            let totalCarbs = 0;
            let totalFat = 0;
            const resolvedItems = [];

            let foodsArray = [];
            if (Array.isArray(data)) {
                foodsArray = data;
            } else if (data && typeof data === 'object') {
                if (Array.isArray(data.foods)) {
                    foodsArray = data.foods;
                } else if (data.foods && Array.isArray(data.foods.food)) {
                    foodsArray = data.foods.food;
                } else if (data.foods && typeof data.foods.food === 'object') {
                    foodsArray = [data.foods.food];
                } else if (data.food && Array.isArray(data.food)) {
                    foodsArray = data.food;
                } else if (data.food && typeof data.food === 'object') {
                    foodsArray = [data.food];
                }
            }

            for (const item of foodsArray) {
                const foodData = item.food_data || item;
                let serving = null;

                if (foodData.serving) {
                    serving = foodData.serving;
                } else if (foodData.servings) {
                    if (Array.isArray(foodData.servings.serving)) {
                        serving = foodData.servings.serving.find(s => s.is_default === '1' || s.is_default === true) || foodData.servings.serving[0];
                    } else if (foodData.servings.serving) {
                        serving = foodData.servings.serving;
                    }
                } else {
                    serving = foodData;
                }

                if (serving) {
                    const calories = parseFloat(serving.calories || serving.energy || 0);
                    const protein = parseFloat(serving.protein || 0);
                    const carbs = parseFloat(serving.carbohydrate || serving.carbs || 0);
                    const fat = parseFloat(serving.fat || serving.total_fat || 0);

                    const sizeMultiplier = parseFloat(item.serving_size || item.quantity || 1);

                    const itemCalories = calories * sizeMultiplier;
                    const itemProtein = protein * sizeMultiplier;
                    const itemCarbs = carbs * sizeMultiplier;
                    const itemFat = fat * sizeMultiplier;

                    totalCalories += itemCalories;
                    totalProtein += itemProtein;
                    totalCarbs += itemCarbs;
                    totalFat += itemFat;

                    resolvedItems.push({
                        ingredient: item.original_input || foodData.food_name || 'unknown',
                        food_name: foodData.food_name || 'unknown',
                        calories: Math.round(itemCalories),
                        protein: Math.round(itemProtein),
                        carbs: Math.round(itemCarbs),
                        fat: Math.round(itemFat)
                    });
                }
            }

            return res.json({
                calories: Math.round(totalCalories),
                protein: Math.round(totalProtein),
                carbs: Math.round(totalCarbs),
                fat: Math.round(totalFat),
                items: resolvedItems,
                unresolved: []
            });
        }

        // -------------------------------------------------------------
        // OPTION B: Free Search-and-Sum Fallback (Default)
        // -------------------------------------------------------------
        let totalCalories = 0;
        let totalProtein = 0;
        let totalCarbs = 0;
        let totalFat = 0;
        // Per-ingredient breakdown, in addition to the aggregate totals below —
        // lets the client rescale an individual ingredient's quantity later
        // (e.g. to hit a daily macro target) using this ingredient's own
        // real per-gram rate, without needing another round trip to FatSecret.
        const resolvedItems = [];
        // Ingredients we couldn't resolve at all (bad search match, API error, etc.) —
        // surfaced back to the caller so a "verified" response doesn't quietly
        // omit foods it failed to look up.
        const unresolvedIngredients = [];

        for (let ingIndex = 0; ingIndex < cleanIngredients.length; ingIndex++) {
            /**
             * ⚠️ NOBODY IS LISTENING, SO STOP SPENDING. Neither loop used to
             * check, so a client that hung up — or gave up at its own 180s
             * ceiling — left this working through the rest of the array at up
             * to five upstream calls an ingredient, with the answer going
             * nowhere. That is the "keeps spending after the client leaves"
             * half of H3, and it is the half an attacker gets for free: open,
             * send sixty ingredients, disconnect, repeat.
             *
             * ⚠️ IT DOES NOT CANCEL THE CALL ALREADY IN FLIGHT, deliberately.
             * Threading an AbortController through `fatSecretPost` and both
             * Gemini helpers would save at most one request per abort, and
             * each is individually bounded by its own timeout. Not starting
             * the next one is where the saving is.
             */
            if (aborted()) {
                console.warn(`[Nutrition] stopped at ingredient ${ingIndex + 1} of ${cleanIngredients.length} after disconnect`);
                return;
            }
            const ingStr = cleanIngredients[ingIndex];
            const foodCore = cleanFoodCores[ingIndex];
            // Small pacing gap between ingredients (not before the first one) so a
            // big multi-day plan doesn't fire a burst of requests back-to-back and
            // trip a rate limit in the first place - cheap insurance on top of the
            // retry-with-backoff below.
            if (resolvedItems.length + unresolvedIngredients.length > 0) {
                await new Promise(resolve => setTimeout(resolve, 120));
            }

            const parsedIng = parseIngredient(ingStr);
            console.log(`[Free Search] Processing: "${ingStr}" -> Parsed:`, parsedIng);

            // A real single-meal serving should never be kilogram-scale (0.3kg chicken
            // breast is just 300g, and the AI's prompt asks for gram-scale portions
            // directly). If "kg" shows up at all, that's a sign of a malformed/hallucinated
            // quantity upstream, not a genuine recommendation - reject it outright rather
            // than silently computing through it (the math is correct either way, see
            // toGrams above, but a correct answer to an implausible question is still
            // wrong). This surfaces as a normal verification failure so the plan gets
            // regenerated instead of quietly serving an unrealistic portion.
            if (parsedIng.unit === 'kg' || parsedIng.unit === 'kilogram' || parsedIng.unit === 'kilograms') {
                console.warn(`[Free Search] Rejecting implausible kilogram-scale ingredient: "${ingStr}"`);
                unresolvedIngredients.push(ingStr);
                continue;
            }

            // Cache hit: skip both network calls entirely for a food name we've already
            // resolved (in this request or an earlier one). `resolveMacros` below still runs
            // fresh every time since it's pure local math over the parsed quantity - only the
            // network lookups (search + detail) are what get skipped.
            const searchCacheKey = parsedIng.food;
            let foodItem = foodSearchCache.get(searchCacheKey);
            let searchWasCached = !!foodItem;

            if (!foodItem) {
                // Primary search: the food phrase exactly as the ingredient wrote it,
                // cooking-method words included ("baked potato", "boiled potatoes") -
                // those words select the correct database entry. Fallback search: the
                // mechanically-simplified term with leading descriptors stripped, tried
                // only when the full phrase matched nothing at all.
                foodItem = await searchFoodItem(parsedIng.food, token, foodCore);
                /* ⚠️ CHECKED AGAIN HERE, not only at the top of the loop. One
                   iteration is up to three `searchFoodItem` calls, each of
                   which can run `pickBestFoodMatchWithAI` — so a check only at
                   the top honours a disconnect a whole iteration late, which
                   on this route is most of the cost. */
                if (!foodItem && parsedIng.foodSimplified && !aborted()) {
                    console.log(`[Free Search] No result for "${parsedIng.food}", retrying simplified: "${parsedIng.foodSimplified}"`);
                    foodItem = await searchFoodItem(parsedIng.foodSimplified, token, foodCore);
                }
                // Last-resort fallback: search on food_core itself. It's the AI's own
                // judgment of the food's minimal identity, already stripped of style/prep
                // words ("shredded", "minced"...) the same way it strips "fresh" - a better
                // simplification than fillerWords' fixed list could ever mechanically
                // guess, and it catches phrases fillerWords has no entry for at all (e.g.
                // "shredded coconut" -> foodSimplified stays null since "shredded" isn't in
                // that list, so this is the only fallback that ever fires for it). Skipped
                // when it's identical to a term already tried, to avoid a redundant search.
                if (!foodItem && foodCore) {
                    const alreadyTried = [parsedIng.food, parsedIng.foodSimplified]
                        .filter(Boolean)
                        .map(s => s.trim().toLowerCase());
                    const coreNormalized = foodCore.trim().toLowerCase();
                    if (coreNormalized && !alreadyTried.includes(coreNormalized) && !aborted()) {
                        console.log(`[Free Search] No result for "${parsedIng.food}", retrying with food_core: "${foodCore}"`);
                        foodItem = await searchFoodItem(foodCore, token, foodCore);
                    }
                }
                if (!foodItem) {
                    console.warn(`[Free Search] No search result found for "${parsedIng.food}"`);
                    unresolvedIngredients.push(ingStr);
                    continue;
                }
                foodSearchCache.set(searchCacheKey, foodItem);
            } else {
                console.log(`[Free Search] Cache hit for search "${searchCacheKey}" -> "${foodItem.food_name}" (0 API calls)`);
            }

            // Pull the full, structured serving list for this food via food.get rather than
            // relying on the single free-text description from foods.search. Every serving
            // here carries a metric_serving_amount/metric_serving_unit (g/ml/oz) straight from
            // FatSecret, so we can scale precisely instead of guessing conversions from text.
            let macros = null;
            let servings = foodDetailCache.get(foodItem.food_id);
            if (servings) {
                if (!searchWasCached) {
                    console.log(`[Free Search] Cache hit for food.get on food_id ${foodItem.food_id} (0 API calls)`);
                }
                macros = resolveMacros(servings, parsedIng);
            } else {
                try {
                    // Same retry-on-refusal path as the search above: a food.get
                    // that leaves from the refused egress IP is not a missing
                    // food either. See fatSecretPost.
                    const detail = await fatSecretPost({
                        method: 'food.get',
                        food_id: foodItem.food_id,
                        format: 'json'
                    }, token, `food.get ${foodItem.food_id}`);

                    if (detail.ok) {
                        const detailData = detail.data;
                        if (!fatSecretError(detailData, `food.get ${foodItem.food_id}`)) {
                            servings = normalizeServings(detailData.food?.servings);
                            if (servings.length > 0) {
                                foodDetailCache.set(foodItem.food_id, servings);
                                macros = resolveMacros(servings, parsedIng);
                            }
                        }
                    } else {
                        console.warn(`[Free Search] food.get failed for food_id ${foodItem.food_id}:`, detail.status);
                    }
                } catch (detailErr) {
                    console.warn(`[Free Search] food.get error for food_id ${foodItem.food_id}:`, detailErr.message);
                }
            }

            // Fallback: parse the plain-text search description if food.get was unavailable
            // or didn't give us anything usable (e.g. transient API error).
            if (!macros && foodItem.food_description) {
                const servingDetails = parseFoodDescription(foodItem.food_description);
                if (servingDetails) {
                    const ingUnit = parsedIng.unit ? parsedIng.unit.toLowerCase() : null;
                    const servUnit = servingDetails.servingUnit ? servingDetails.servingUnit.toLowerCase() : null;

                    let scalingFactor;
                    if (ingUnit === servUnit ||
                        (ingUnit && servUnit && (ingUnit.startsWith(servUnit) || servUnit.startsWith(ingUnit)))) {
                        scalingFactor = parsedIng.quantity / servingDetails.servingAmount;
                    } else {
                        // Never divide a raw quantity in one unit by a serving amount in another
                        // unit - normalize both sides to grams first. Real metric units
                        // (g/kg/oz/ml, any full/plural form) go through toGrams for an exact
                        // conversion; genuine measuring-unit words (slice, cup...) fall back to
                        // the CONVERSIONS approximation table. There's no `servings` array in
                        // this text-description-only path (unlike resolveMacros above), so
                        // pickReferenceServing can't help here - a missing/unrecognized unit
                        // still has nothing better than the flat 100g default.
                        const ingredientGrams = toGrams(parsedIng.quantity, ingUnit)
                            ?? parsedIng.quantity * (CONVERSIONS[ingUnit] || 100);
                        const servingGrams = toGrams(servingDetails.servingAmount, servUnit)
                            ?? servingDetails.servingAmount * (CONVERSIONS[servUnit] || 100);
                        scalingFactor = ingredientGrams / servingGrams;
                    }

                    macros = {
                        calories: servingDetails.calories * scalingFactor,
                        protein: servingDetails.protein * scalingFactor,
                        carbs: servingDetails.carbs * scalingFactor,
                        fat: servingDetails.fat * scalingFactor,
                        via: 'text-description fallback'
                    };
                }
            }

            if (!macros) {
                console.warn(`[Free Search] Could not resolve macros for "${ingStr}"`);
                unresolvedIngredients.push(ingStr);
                continue;
            }

            console.log(`[Free Search] Matched: "${foodItem.food_name}" via ${macros.via} -> ${macros.calories.toFixed(1)} kcal`);

            totalCalories += macros.calories;
            totalProtein += macros.protein;
            totalCarbs += macros.carbs;
            totalFat += macros.fat;

            // Real-world grounding for realistic-portion clamping downstream: the food's
            // natural reference serving (e.g. "1 slice" = 28g), plus how many real grams
            // equal ONE unit of whatever quantity the ingredient string itself used - null
            // for both when food.get never ran (rare text-description fallback), which the
            // client falls back gracefully for.
            const referenceServing = pickReferenceServing(servings);
            const gramsPerOriginalUnit = macros.referenceGrams != null && parsedIng.quantity > 0
                ? macros.referenceGrams / parsedIng.quantity
                : null;

            resolvedItems.push({
                ingredient: ingStr,
                food_name: foodItem.food_name || parsedIng.food,
                calories: Math.round(macros.calories),
                protein: Math.round(macros.protein),
                carbs: Math.round(macros.carbs),
                fat: Math.round(macros.fat),
                referenceServingGrams: referenceServing ? Math.round(referenceServing.grams) : null,
                referenceServingUnit: referenceServing ? referenceServing.unit : null,
                gramsPerOriginalUnit
            });
        }

        return res.json({
            calories: Math.round(totalCalories),
            protein: Math.round(totalProtein),
            carbs: Math.round(totalCarbs),
            fat: Math.round(totalFat),
            items: resolvedItems,
            unresolved: unresolvedIngredients
        });

    } catch (err) {
        console.error("FatSecret Proxy integration failure:", err);
        return res.status(500).json({ error: "Internal proxy server error: " + err.message });
    }
}));

// Last-resort estimate endpoint - the caller (DietSetupFlow) only reaches for
// this after /api/nutrition/analyze has already failed to resolve an
// ingredient AND a repair attempt with a different, more common ingredient
// has ALSO failed. Deliberately separate from /api/nutrition/analyze rather
// than an automatic fallback inside it, so a real database match is always
// preferred and this only fires for the genuinely unresolvable remainder.
app.post('/api/nutrition/estimate', wrap(requireUser), wrap(requireSubscription), express.json({ limit: '100kb' }), validateIngredients, wrap(rateLimitFixed('nutrition', ingredientCost)), wrap(async (req, res) => {
    /* Validated, capped, paired and costed by `validateIngredients` before the
       limiter ran — see it for why that order matters. */
    const { paired } = req.nutrition;

    /**
     * Has the caller gone? Checked where it can save an upstream call.
     *
     * ⚠️ NOT `req.destroyed`. That is what this was, and it shipped broken for
     * one commit: `req.destroyed` goes true as soon as the request BODY has
     * been fully consumed, which `express.json` does before the handler ever
     * runs. It says nothing about the client. Measured on node v24.15.0, one
     * connected curl that waits for its answer:
     *
     *     t=0     req.destroyed=false  res.destroyed=false  closeFlag=false
     *     t=150   req.destroyed=TRUE   res.destroyed=false  closeFlag=false
     *     t=1150  req.destroyed=TRUE   res.destroyed=false  closeFlag=false
     *
     * and the same client aborting at 0.4s:
     *
     *     t=1150  req.destroyed=TRUE   res.destroyed=TRUE   closeFlag=TRUE
     *
     * So every request with two or more ingredients stopped after the first
     * and never answered — the loop returned without writing, and the caller
     * hung until its own 180s timeout.
     *
     * ⚠️ A LATCHED FLAG, NOT `res.destroyed`, THOUGH BOTH WORK. The table
     * above shows `res.destroyed` and `req.socket.destroyed` are both correct
     * signals. This uses the close event instead for one reason: the nutrition
     * logger a few hundred lines up decides CLIENT ABORTED with exactly this
     * test — `res.on('close')` with `!res.writableEnded`. Sharing the idiom
     * means the log line and the loop cannot disagree about what an abort is.
     * Picking a second `.destroyed` property would also be the same bet that
     * just lost: trusting a property name to mean what it sounds like.
     *
     * `!res.writableEnded` is what separates an abort from a normal finish —
     * `close` fires for both, and nothing has been written while the loop runs.
     */
    let clientGone = false;
    res.on('close', () => { if (!res.writableEnded) clientGone = true; });
    const aborted = () => clientGone;

    const items = [];
    const failed = [];

    for (let i = 0; i < paired.length; i++) {
        /* One Gemini call per ingredient here, so the top of the loop is the
           only place worth checking — see the longer note on /analyze. */
        if (aborted()) {
            console.warn(`[Nutrition] stopped at ingredient ${i + 1} of ${paired.length} after disconnect`);
            return;
        }
        // Same pacing gap as /api/nutrition/analyze - avoid bursting requests.
        if (i > 0) await new Promise(resolve => setTimeout(resolve, 120));

        const { ingredient, foodCore } = paired[i];
        try {
            const item = await estimateIngredientMacrosWithAI(ingredient, foodCore);
            if (item) {
                console.log(`[AI Estimate] "${ingredient}" -> ${item.calories} kcal (P${item.protein}/C${item.carbs}/F${item.fat})`);
                items.push(item);
            } else {
                console.warn(`[AI Estimate] Implausible or unparseable estimate for "${ingredient}"`);
                failed.push(ingredient);
            }
        } catch (err) {
            console.warn(`[AI Estimate] Failed to estimate "${ingredient}":`, err.message);
            failed.push(ingredient);
        }
    }

    return res.json({ items, failed });
}));

/**
 * What a caller is told, which is as little as is still true.
 *
 * ⚠️ 413 IS SPLIT OUT because "Bad request." describes it wrongly — the
 * request was well-formed and too big, and that is the one 4xx here a caller
 * can actually act on. The size limit is discoverable by anyone willing to
 * bisect, so naming it discloses nothing.
 */
const errorMessageFor = (status) => {
    if (status >= 500) return 'Internal server error.';
    if (status === 413) return 'Request body too large.';
    return 'Bad request.';
};

/**
 * The last word on any request that threw.
 *
 * ⚠️ REGISTERED AFTER EVERY ROUTE, which is the only position Express accepts
 * for a four-argument handler. Anything above that calls `next(err)` — every
 * `wrap`ped route and middleware, and body-parser's own 400 and 413 — lands
 * here instead of in Express's default page.
 *
 * ⚠️ IT PRESERVES THE STATUS AND REPLACES THE BODY. `err.status` carries
 * body-parser's 413 for an oversized body and 400 for malformed JSON, and
 * flattening those to 500 would turn two honest client errors into a claim
 * that the server broke. Only the BODY is fixed.
 *
 * ⚠️ AND THE FIXED BODY IS WHY THIS CLOSES THE STACK-TRACE LEAK IN CODE
 * RATHER THAN IN A DASHBOARD. Express's default handler prints the stack
 * unless NODE_ENV is 'production'. Whether the host sets that is the host's
 * business and is not asserted here — probing production found no stack, but
 * nothing in this repo guarantees it, and the next place this runs (staging,
 * a local tunnel, a second project) would leak paths and line numbers with no
 * warning. This makes it a property of the code instead.
 *
 * ⚠️ THE STATUS IS CLAMPED TO 400–599, and that line is load-bearing. An
 * error carrying `status: 'abc'` made `res.status()` ITSELF throw, Express
 * fell back to its default handler, and the stack page this exists to
 * suppress went out anyway — the leak, reintroduced by the fix. `status: 999`
 * merely reached the client as 999. Anything that is not a plausible HTTP
 * error code is the server's problem, so it reads as 500.
 *
 * ⚠️ THE BODY CARRIES A REQUEST ID AND THE LOG LINE CARRIES THE SAME ONE.
 * The message is deliberately uninformative — the app maps status to its own
 * copy and never shows this text — so the id is the only thread back from
 * "it failed" to the stack that explains why. It is random per error, says
 * nothing about the request, and the client's `proxyError` already logs the
 * whole body, so it reaches the debug console with no client change.
 */
app.use((err, req, res, next) => {
    /* A response already on the wire cannot be rewritten — hand it back to
       Express, whose default handler will close the connection. */
    if (res.headersSent) return next(err);

    /* Only a plausible HTTP error code survives; see the clamp note above. */
    const raw = err?.status ?? err?.statusCode;
    const status = Number.isInteger(raw) && raw >= 400 && raw <= 599 ? raw : 500;

    /* Short, random, meaningless on its own — the join between this log line
       and whatever the caller reports. */
    const requestId = crypto.randomUUID().slice(0, 8);

    console.error(
        `[error] ${requestId} ${req.method} ${req.path} -> ${status}:`,
        err?.stack || err?.message || err,
    );
    res.status(status).json({
        error: { message: errorMessageFor(status), requestId },
    });
});

/**
 * The net, and only the net.
 *
 * ⚠️ IT PREVENTS THE EXIT AND NOTHING ELSE. Node 22 terminates on an unhandled
 * rejection; this stops that, so one bad request can no longer restart the
 * process and wipe `aiHits` with it. It does NOT answer the request whose
 * promise rejected — that client waits out its own timeout. `wrap` above is
 * what turns a rejection into a 500; this is what stops the service dying
 * while something nobody wrapped is found.
 *
 * ⚠️ A PROCESS KEPT ALIVE HERE IS IN AN UNDEFINED STATE, which is the usual
 * argument against doing this. It is accepted because this server is
 * stateless apart from the rate-limit counters — and those are precisely what
 * a restart destroys, so staying up is the safer failure.
 */
process.on('unhandledRejection', (err) => {
    console.error('[fatal] unhandled rejection, staying up:', err?.message || err);
});

app.listen(PORT, () => {
    console.log(`FORMnFUEL FatSecret Proxy Server running on port ${PORT}`);

    /**
     * Which mode the paywall came up in, stated by the process that loaded it.
     *
     * ⚠️ THE FLAG IS A SILENT, CASE-SENSITIVE MATCH ON `'true'`, and that is
     * the whole reason this line exists. `requireSubscription` tests
     * `!== 'true'`, so `True`, `TRUE`, `1` and `yes` all leave enforcement OFF
     * — with the variable present in the dashboard, spelled correctly, looking
     * exactly like it is working. There is no error, no warning, and no
     * difference visible anywhere except by going unsubscribed and trying to
     * generate a plan.
     *
     * Reported the same way as the `[ratelimit] OVERRIDE:` lines above, and
     * for the same reason: the deploy log should say what this server actually
     * loaded, not what someone believes they set. That is how the limits were
     * confirmed to be on their defaults in production.
     *
     * ⚠️ IT REPORTS, IT DOES NOT DECIDE. The test below must stay a mirror of
     * the one in `requireSubscription` — if that one changes, this says the
     * wrong thing confidently, which is worse than saying nothing.
     */
    const enforcing = process.env.REQUIRE_SUBSCRIPTION === 'true';
    const raw = process.env.REQUIRE_SUBSCRIPTION;
    if (enforcing) {
        console.log('[auth] subscription enforcement ON — paid operations require an active subscription');
    } else if (raw !== undefined && raw !== '') {
        /* Set, but not to the one value that counts. This is the failure the
           line exists to catch, so it names what was found. */
        console.warn(
            `[auth] subscription enforcement OFF — REQUIRE_SUBSCRIPTION="${raw}" is not the exact string "true". ` +
            'Every signed-in account may call paid operations.',
        );
    } else {
        console.warn('[auth] subscription enforcement OFF — every signed-in account may call paid operations');
    }
});
