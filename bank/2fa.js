import { createClient } from "@supabase/supabase-js";
import jwt from "jsonwebtoken";
import ws from "ws";

// 1. SYSTEM ENVIRONMENT INITIALIZATION
const SUPABASE_URL = process.env.PUBLIC_SUPABASE_URL || process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY;
const JWT_SECRET = process.env.JWT_SECRET;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY || !JWT_SECRET) {
    throw new Error("CRITICAL CONFIGURATION ERROR: Supabase or JWT credential mappings are unassigned inside environment properties.");
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false },
    realtime: { transport: ws }
});

/**
 * Controller Route Handler for Toggling User 2FA Security State
 */
export default async function twoFactorAuthHandler(req, res) {
    // A. CORS & OPTIONS METHOD INTERCEPTORS
    const requestOrigin = req.headers.origin;
    if (requestOrigin) res.setHeader("Access-Control-Allow-Origin", requestOrigin);
    res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

    if (req.method === "OPTIONS") return res.status(200).end();
    if (req.method !== "POST") return res.status(405).json({ success: false, error: "Method blocked." });

    // B. AUTHENTICATION & SECURITY VALIDATION
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ success: false, error: "Access Denied: Missing authorization headers." });
    }

    const token = authHeader.split(" ")[1];
    let decodedClaims;
    try {
        decodedClaims = jwt.verify(token, JWT_SECRET);
    } catch (err) {
        return res.status(401).json({ success: false, error: "Session token expired or corrupted." });
    }

    const verifiedUuid = decodedClaims.uuid || decodedClaims.id || (decodedClaims.user && decodedClaims.user.id);
    if (!verifiedUuid) {
        return res.status(401).json({ success: false, error: "Identity verification failed." });
    }

    // C. EXTRACT PAYLOAD & UPDATE DB
    const { enable2fa } = req.body;

    if (typeof enable2fa !== "boolean") {
        return res.status(400).json({ success: false, error: "Invalid payload parameter 'enable2fa' must be a boolean." });
    }

    try {
        // Update 2fa column in Supabase users table
        const { error: dbError } = await supabase
            .from('users')
            .update({ "2fa": enable2fa }) // Quoted key matches postgres schema '2fa'
            .eq('uuid', verifiedUuid);

        if (dbError) throw dbError;

        return res.status(200).json({
            success: true,
            message: `2FA security status successfully updated to ${enable2fa}`,
            is2faEnabled: enable2fa
        });

    } catch (globalExecutionFault) {
        console.error("❌ Global transaction thread logic failure:", globalExecutionFault);
        return res.status(500).json({
            success: false,
            error: globalExecutionFault.message || "Internal database routing network fault."
        });
    }
}