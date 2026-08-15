const express = require('express');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 4000;

// Config Toggle: Set to true only if you purchase the $250/mo NLP add-on from FatSecret
const USE_NATIVE_NLP = process.env.USE_NATIVE_NLP === 'true';

app.use(cors());
// 25mb, not the 100kb default: /api/ai/generate forwards Gemini requests that
// can carry up to four body-composition photos as base64 inlineData. This has
// to be set HERE rather than as a per-route express.json({limit}) — this global
// parser runs first for every route, so it would 413 the request before any
// route-level limit was ever consulted (confirmed: a 2MB body was rejected with
// a route-level 25mb limit in place).
app.use(express.json({ limit: '25mb' }));

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
const { createClient } = require('@supabase/supabase-js');

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
        if (error || !data?.user) {
            return res.status(401).json({ error: { message: 'Invalid or expired token.' } });
        }
        // Downstream handlers and logs can attribute spend to a real account.
        req.userId = data.user.id;
        return next();
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
// ingredient - its own gram estimate for the stated quantity, plus a realistic per-meal max.
// Stripped out before any unit/food parsing so it never pollutes the FatSecret search query
// or the unit-matching logic, and pulled out separately as aiGrams/aiMax so resolveMacros can
// anchor its gram-normalization and plausibility checks on the AI's own number instead of the
// generic CONVERSIONS table guess.
const GRAMS_ANNOTATION_REGEX = /\(\s*([\d.]+)\s*g\s*,\s*max\s*([\d.]+)\s*g\s*\)\s*$/i;

function stripGramsAnnotation(str) {
    const match = str.match(GRAMS_ANNOTATION_REGEX);
    if (!match) return { clean: str, aiGrams: null, aiMax: null };
    return {
        clean: str.replace(GRAMS_ANNOTATION_REGEX, '').trim(),
        aiGrams: parseFloat(match[1]),
        aiMax: parseFloat(match[2])
    };
}

/**
 * Helper to parse an ingredient string into a structured object containing quantity, unit, and food item name.
 */
function parseIngredient(str) {
    const { clean: withoutAnnotation, aiGrams, aiMax } = stripGramsAnnotation(str.trim());
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
        aiGrams,
        aiMax
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
const GEMINI_MODEL = process.env.GEMINI_MODEL || 'gemini-3.6-flash';

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
            `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent?key=${apiKey}`,
            {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    contents: [{ parts: [{ text: prompt }] }],
                    generationConfig: { temperature: 0 },
                }),
                signal: controller.signal,
            }
        );
        if (!response.ok) throw new Error(`Gemini verification call returned ${response.status}`);
        const data = await response.json();
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
            `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent?key=${apiKey}`,
            {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    contents: [{ parts: [{ text: prompt }] }],
                    generationConfig: { temperature: 0 },
                }),
                signal: controller.signal,
            }
        );
        if (!response.ok) throw new Error(`Gemini estimate call returned ${response.status}`);
        const data = await response.json();
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
app.get('/health', async (req, res) => {
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
});

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
// Body-size note: the limit for this route is set on the GLOBAL express.json()
// at the top of this file, not here — see the comment there for why a
// route-level limit doesn't work.
app.post('/api/ai/generate', requireUser, async (req, res) => {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
        return res.status(500).json({ error: { message: 'GEMINI_API_KEY not configured on the proxy server.' } });
    }

    const { contents, generationConfig, model } = req.body || {};
    if (!Array.isArray(contents) || contents.length === 0) {
        return res.status(400).json({ error: { message: 'Request must include a non-empty "contents" array.' } });
    }

    // Allow the caller to pick a model, but only from a known-good set — an
    // unvalidated passthrough would let anyone who can reach this proxy bill us
    // for an arbitrarily expensive model.
    const ALLOWED_MODELS = new Set(['gemini-3.6-flash', 'gemini-3.1-flash-lite', 'gemini-3.5-flash', 'gemini-3.5-flash-lite']);
    const chosenModel = model && ALLOWED_MODELS.has(model) ? model : GEMINI_MODEL;

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
     */
    req.on('close', () => {
        if (!res.writableEnded) {
            console.warn(
                `[AI Proxy] CLIENT ABORTED after ${Date.now() - startedAt}ms — ` +
                `model ${chosenModel}, prompt ${promptChars} chars. ` +
                `This is the app's 180s deadline firing.`
            );
        }
    });

    try {
        // No timeout here on purpose: the client already owns the deadline via
        // its own AbortController, and aborting client-side tears down this
        // request too. A second, shorter timeout here would just truncate long
        // (but healthy) generations — a 3.6-flash draft legitimately runs ~70s.
        const geminiResponse = await fetch(
            `https://generativelanguage.googleapis.com/v1beta/models/${chosenModel}:generateContent?key=${apiKey}`,
            {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ contents, generationConfig }),
            }
        );

        // Mirror Gemini's status so the app's existing handling (429 quota
        // messaging, 5xx retry in fetchGeminiWithRetry) keeps working unchanged.
        const data = await geminiResponse.json().catch(() => ({}));
        const elapsedMs = Date.now() - startedAt;
        const replyChars = (data?.candidates?.[0]?.content?.parts?.[0]?.text || '').length;

        // One line per call, always — a slow SUCCESS is the number that says
        // whether 180s is a sane ceiling or a coin toss, and it never shows up
        // if only failures are logged. Note the app retries 5xx up to twice
        // INSIDE its single 180s budget, so several of these lines can belong
        // to one user-visible generation.
        console.log(
            `[AI Proxy] ${chosenModel} ${geminiResponse.status} in ${elapsedMs}ms — ` +
            `prompt ${promptChars} chars, reply ${replyChars} chars`
        );
        if (!geminiResponse.ok) {
            console.warn(`[AI Proxy] Gemini returned ${geminiResponse.status} for model ${chosenModel}`);
        }
        return res.status(geminiResponse.status).json(data);
    } catch (err) {
        console.error(`[AI Proxy] Request failed after ${Date.now() - startedAt}ms:`, err.message || err);
        return res.status(502).json({ error: { message: `Could not reach the AI service: ${err.message || err}` } });
    }
});

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
 * Registered BEFORE the handlers so it wraps them, and after the body parser so
 * `ingredients` is populated — the count is what makes a slow line
 * interpretable, since 40 ingredients legitimately takes longer than 6.
 */
app.use(['/api/nutrition/analyze', '/api/nutrition/estimate'], (req, res, next) => {
    const startedAt = Date.now();
    const count = Array.isArray(req.body && req.body.ingredients) ? req.body.ingredients.length : 0;

    res.on('finish', () => {
        console.log(`[Nutrition] ${req.path} ${res.statusCode} in ${Date.now() - startedAt}ms — ${count} ingredient(s)`);
    });
    // The app gives up at 180s; from here that is only ever a closed socket.
    res.on('close', () => {
        if (!res.writableEnded) {
            console.warn(`[Nutrition] CLIENT ABORTED ${req.path} after ${Date.now() - startedAt}ms — ${count} ingredient(s)`);
        }
    });
    next();
});

// Nutrition Analysis Endpoint
app.post('/api/nutrition/analyze', requireUser, async (req, res) => {
    const { ingredients, foodCores } = req.body;

    if (!ingredients || !Array.isArray(ingredients)) {
        return res.status(400).json({ error: "ingredients must be an array of strings" });
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
                if (!foodItem && parsedIng.foodSimplified) {
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
                    if (coreNormalized && !alreadyTried.includes(coreNormalized)) {
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
});

// Last-resort estimate endpoint - the caller (DietSetupFlow) only reaches for
// this after /api/nutrition/analyze has already failed to resolve an
// ingredient AND a repair attempt with a different, more common ingredient
// has ALSO failed. Deliberately separate from /api/nutrition/analyze rather
// than an automatic fallback inside it, so a real database match is always
// preferred and this only fires for the genuinely unresolvable remainder.
app.post('/api/nutrition/estimate', requireUser, async (req, res) => {
    const { ingredients, foodCores } = req.body;

    if (!ingredients || !Array.isArray(ingredients)) {
        return res.status(400).json({ error: "ingredients must be an array of strings" });
    }

    const paired = ingredients
        .map((ing, i) => ({
            ingredient: (ing || '').trim(),
            foodCore: Array.isArray(foodCores) ? (foodCores[i] || null) : null
        }))
        .filter(p => p.ingredient.length > 0);

    const items = [];
    const failed = [];

    for (let i = 0; i < paired.length; i++) {
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
});

app.listen(PORT, () => {
    console.log(`FORMnFUEL FatSecret Proxy Server running on port ${PORT}`);
});
