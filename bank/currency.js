/**
 * ==========================================================================
 * ONFLEX FINANCE CENTRALIZED CURRENCY REGISTRY MAP
 * Translates dropdown form symbols/values straight to ISO 4217 standard codes.
 * ==========================================================================
 */
export const currencyMap = {
    // Major Global Reserve Currencies
    "$": "USD",
    "€": "EUR",
    "£": "GBP",
    "CHF": "CHF",

    // Stable Commonwealth & Top Tier Dollars
    "CA$": "CAD",
    "A$": "AUD",
    "NZ$": "NZD",
    "S$": "SGD",
    "HK$": "HKD",

    // High-Volume Asian Markets
    "¥": "JPY",
    "CN¥": "CNY",
    "₩": "KRW",
    "₹": "INR",

    // Stable Middle Eastern & Gulf Currencies
    "AED": "AED",
    "SAR": "SAR",
    "QAR": "QAR",
    "KWD": "KWD",
    "₪": "ILS",

    // Key European & Nordic Markets
    "SEkr": "SEK",
    "NOkr": "NOK",
    "DKkr": "DKK",
    "zł": "PLN",
    "₽": "RUB",
    "₺": "TRY",

    // Strategic Emerging Markets
    "R$": "BRL",
    "Mex$": "MXN",
    "R": "ZAR",
    "₦": "NGN"
};

/**
 * Normalizes user symbols or selected list values down to 3-letter ISO standards.
 * Falls back to "USD" if the mapping fails.
 * @param {string} rawInput 
 * @returns {string}
 */
export function getIsoCode(rawInput) {
    if (!rawInput) return "USD";
    const cleaned = String(rawInput).trim();
    if (currencyMap[cleaned]) {
        return currencyMap[cleaned];
    }
    // Fallback: strip standard symbols and try matching clean string directly
    const directFallback = cleaned.replace(/[$€£]/g, "").toUpperCase();
    return directFallback.length === 3 ? directFallback : "USD";
}