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
    "¥": "JPY",       // Note: Standard dropdown select logic assigns default symbol variant
    "CN¥": "CNY",     // Explicit custom Chinese Yuan mapping string
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
 * Helper utility function to parse any mixed profile string values securely
 */
export function getIsoCode(symbol) {
    if (!symbol) return "USD";
    const cleanSymbol = String(symbol).trim();

    // Return matched value or fallback gracefully to standard base
    return currencyMap[cleanSymbol] || "USD";
}