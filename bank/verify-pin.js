import { createClient } from "@supabase/supabase-js";
import jwt from "jsonwebtoken";
import ws from "ws";

const SUPABASE_URL = process.env.PUBLIC_SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const JWT_SECRET = process.env.JWT_SECRET;

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false },
    realtime: { transport: ws }
});

export default async function handler(req, res) {
    console.log("\n=========================================");
    console.log("📌 [VERIFY-PIN] INCOMING REQUEST DETECTED");
    console.log("METHOD:", req.method);
    console.log("HEADERS:", req.headers);
    console.log("BODY:", req.body);
    console.log("=========================================\n");

    // -------------------------------------------------------------------------
    // 1. CORS & PREFLIGHT HANDLING
    // -------------------------------------------------------------------------
    const requestOrigin = req.headers.origin;
    if (requestOrigin) {
        res.setHeader("Access-Control-Allow-Origin", requestOrigin);
    }

    res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Setting-Target, X-Requested-With, Accept");
    res.setHeader("Access-Control-Allow-Credentials", "true");

    if (req.method === "OPTIONS") {
        console.log("📌 [VERIFY-PIN] Handled CORS OPTIONS preflight.");
        return res.status(200).end();
    }

    if (req.method !== "POST") {
        console.warn("⚠️ [VERIFY-PIN] Blocked non-POST method:", req.method);
        return res.status(405).json({ success: false, error: "Method not allowed." });
    }

    try {
        // -------------------------------------------------------------------------
        // 2. AUTHENTICATION (JWT VALIDATION)
        // -------------------------------------------------------------------------
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            console.error("❌ [VERIFY-PIN] Missing or invalid Authorization header.");
            return res.status(401).json({ success: false, error: "Session token is missing." });
        }

        const token = authHeader.split(" ")[1];
        let decodedToken;
        try {
            decodedToken = jwt.verify(token, JWT_SECRET);
        } catch (err) {
            console.error("❌ [VERIFY-PIN] JWT Verification Error:", err.message);
            return res.status(401).json({ success: false, error: "Session expired or invalid. Please log in again." });
        }

        // -------------------------------------------------------------------------
        // 3. PARAMETER & PAYLOAD EXTRACTION
        // -------------------------------------------------------------------------
        const { pin, user_id } = req.body || {};
        const targetUuid = decodedToken.uuid || user_id;

        if (!pin) {
            console.error("❌ [VERIFY-PIN] No PIN provided in payload.");
            return res.status(400).json({ success: false, error: "PIN payload parameter missing." });
        }

        const formattedPinInput = String(pin).trim();
        if (!/^[0-9]{4}$/.test(formattedPinInput)) {
            console.error("❌ [VERIFY-PIN] PIN layout invalid:", formattedPinInput);
            return res.status(400).json({ success: false, error: "PIN must be exactly 4 digits." });
        }

        // -------------------------------------------------------------------------
        // 4. DATABASE USER LOOKUP
        // -------------------------------------------------------------------------
        const { data: userData, error: userError } = await supabase
            .from("users")
            .select("*")
            .eq("uuid", targetUuid)
            .maybeSingle();

        if (userError || !userData) {
            console.error("❌ [VERIFY-PIN] Database user query failure:", userError?.message);
            return res.status(404).json({ success: false, error: "User profile not found." });
        }

        if (userData.restricted === true || userData.activeuser === false) {
            console.warn(`⚠️ [VERIFY-PIN] User account restricted: ${targetUuid}`);
            return res.status(403).json({
                success: false,
                restricted: true,
                error: "Account access restricted due to security locking conditions."
            });
        }

        const storedPin = userData.pin ? String(userData.pin).trim() : "";

        if (!storedPin) {
            console.warn(`⚠️ [VERIFY-PIN] User ${targetUuid} has no PIN set.`);
            return res.status(400).json({
                success: false,
                error: "No transaction PIN configured for this account. Please set up a PIN in security settings."
            });
        }

        // -------------------------------------------------------------------------
        // 5. ATTEMPT RATELIMIT / LOCKOUT LOGIC
        // -------------------------------------------------------------------------
        if (storedPin !== formattedPinInput) {
            const currentAttempts = (parseInt(userData.attempt2, 10) || 0) + 1;
            const remaining = 5 - currentAttempts;

            console.warn(`⚠️ [VERIFY-PIN] Incorrect PIN entered for ${targetUuid}. Attempt ${currentAttempts}/5`);

            if (remaining <= 0) {
                await supabase
                    .from("users")
                    .update({ restricted: true, activeuser: false, attempt2: 5 })
                    .eq("uuid", userData.uuid);

                return res.status(403).json({
                    success: false,
                    restricted: true,
                    error: "Too many failed PIN attempts. Account locked due to security violation."
                });
            }

            await supabase
                .from("users")
                .update({ attempt2: currentAttempts })
                .eq("uuid", userData.uuid);

            return res.status(401).json({
                success: false,
                error: `Incorrect PIN code. You have ${remaining} attempt(s) remaining.`
            });
        }

        // -------------------------------------------------------------------------
        // 6. SUCCESSFUL VERIFICATION
        // -------------------------------------------------------------------------
        console.log(`✅ [VERIFY-PIN] PIN verified successfully for user ${targetUuid}`);

        await supabase
            .from("users")
            .update({ attempt2: 0 })
            .eq("uuid", userData.uuid);

        const freshToken = jwt.sign(
            { uuid: userData.uuid, email: userData.email },
            JWT_SECRET,
            { expiresIn: "7d" }
        );

        const { password, ...safeUser } = userData;

        return res.status(200).json({
            success: true,
            message: "PIN verified successfully.",
            token: freshToken,
            user: safeUser
        });

    } catch (err) {
        console.error("❌ [VERIFY-PIN] Fatal Exception:", err.message);
        return res.status(500).json({ success: false, error: err.message || "Internal server error during PIN verification." });
    }
}