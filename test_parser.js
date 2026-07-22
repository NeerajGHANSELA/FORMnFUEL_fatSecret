// Test Regex Ingredient Parser

const testIngredients = [
    "3 large eggs",
    "2 slices of whole wheat bread",
    "1 medium banana",
    "150g grilled chicken breast",
    "1 cup cooked jasmine rice",
    "80g broccoli",
    "1 scoop whey protein powder",
    "1 cup unsweetened almond milk"
];

function parseIngredient(str) {
    const clean = str.trim().toLowerCase()
        .replace(/\bof\b/g, '')  // remove "of"
        .replace(/\s+/g, ' ');

    // Match fraction/decimal quantity at the start
    // e.g. "1 1/2", "1.5", "1/2", "2"
    const qtyRegex = /^(\d+\s+\d+\/\d+|\d+\/\d+|\d+\.\d+|\d+)\s*(.*)$/;
    const qtyMatch = clean.match(qtyRegex);
    
    let quantity = 1;
    let rest = clean;
    
    if (qtyMatch) {
        let qtyStr = qtyMatch[1];
        rest = qtyMatch[2];
        
        if (qtyStr.includes('/')) {
            if (qtyStr.includes(' ')) {
                // e.g. "1 1/2"
                const parts = qtyStr.split(/\s+/);
                const integer = parseInt(parts[0]);
                const fracParts = parts[1].split('/');
                quantity = integer + parseFloat(fracParts[0]) / parseFloat(fracParts[1]);
            } else {
                // e.g. "1/2"
                const parts = qtyStr.split('/');
                quantity = parseFloat(parts[0]) / parseFloat(parts[1]);
            }
        } else {
            quantity = parseFloat(qtyStr);
        }
    }

    // Match unit words
    const units = [
        'g', 'gram', 'grams', 
        'kg', 'kilogram', 'kilograms',
        'ml', 'milliliter', 'milliliters',
        'oz', 'ounce', 'ounces',
        'cup', 'cups', 
        'tbsp', 'tablespoon', 'tablespoons',
        'tsp', 'teaspoon', 'teaspoons',
        'slice', 'slices', 
        'piece', 'pieces',
        'scoop', 'scoops',
        'can', 'cans',
        'bottle', 'bottles',
        'head', 'heads',
        'clove', 'cloves',
        'large', 'medium', 'small', 'whole'
    ];
    
    // Create unit matching regex: starting with one of these unit words
    let unit = null;
    let food = rest;
    
    const words = rest.split(/\s+/);
    if (words.length > 0 && units.includes(words[0])) {
        unit = words[0];
        food = words.slice(1).join(' ');
    } else {
        // Check if quantity was stuck to unit, e.g. "150g"
        // In that case, the first match of qtyRegex would leave "g grilled chicken..."
        const stuckUnitRegex = /^([a-zA-Z]+)\s*(.*)$/;
        const stuckMatch = rest.match(stuckUnitRegex);
        if (stuckMatch && units.includes(stuckMatch[1])) {
            unit = stuckMatch[1];
            food = stuckMatch[2];
        }
    }

    // Clean up food name (remove cooked, diced, raw adjectives if they start the name)
    const fillerWords = ['cooked', 'raw', 'grilled', 'boiled', 'baked', 'fried', 'diced', 'sliced', 'chopped', 'fresh', 'organic'];
    let foodWords = food.split(/\s+/);
    while (foodWords.length > 0 && fillerWords.includes(foodWords[0])) {
        foodWords.shift();
    }
    food = foodWords.join(' ');

    return {
        original: str,
        quantity,
        unit,
        food: food || rest
    };
}

function parseFoodDescription(desc) {
    // Example: "Per 100g - Calories: 147kcal | Fat: 9.94g | Carbs: 0.77g | Protein: 12.58g"
    // Example: "Per 1 serving - Calories: 190kcal | Fat: 18.00g | Carbs: 0.00g | Protein: 6.00g"
    const regex = /Per\s+([\d.]+)?\s*([a-zA-Z]+)?\s*-\s*Calories:\s*(\d+)kcal\s*\|\s*Fat:\s*([\d.]+)g\s*\|\s*Carbs:\s*([\d.]+)g\s*\|\s*Protein:\s*([\d.]+)g/i;
    const match = desc.match(regex);
    if (!match) return null;

    return {
        servingAmount: parseFloat(match[1] || 1),
        servingUnit: match[2] ? match[2].toLowerCase() : 'serving',
        calories: parseFloat(match[3]),
        fat: parseFloat(match[4]),
        carbs: parseFloat(match[5]),
        protein: parseFloat(match[6])
    };
}

// Dry run test parsing
console.log("Parsing test ingredients:");
testIngredients.forEach(ing => {
    console.log(JSON.stringify(parseIngredient(ing)));
});

console.log("\nParsing test food descriptions:");
const testDescs = [
    "Per 100g - Calories: 147kcal | Fat: 9.94g | Carbs: 0.77g | Protein: 12.58g",
    "Per 1 egg - Calories: 70kcal | Fat: 5.00g | Carbs: 0.00g | Protein: 6.00g",
    "Per 1 serving - Calories: 190kcal | Fat: 18.00g | Carbs: 0.00g | Protein: 6.00g",
    "Per 1 slice - Calories: 79kcal | Fat: 1.00g | Carbs: 15.00g | Protein: 3.00g"
];
testDescs.forEach(desc => {
    console.log(JSON.stringify(parseFoodDescription(desc)));
});
