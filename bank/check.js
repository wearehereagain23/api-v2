import { createClient } from "@supabase/supabase-js";
import ws from "ws";

const SUPABASE_URL = process.env.PUBLIC_SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    throw new Error("CRITICAL SYSTEM CHECK FAULT: Database environment matrix variables missing.");
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false, autoRefreshToken: false },
    realtime: { transport: ws }
});

function applyCors(req, res) {
    const origin = req.headers.origin;

    // Dynamically echo back whichever website is making the request
    if (origin) {
        res.setHeader("Access-Control-Allow-Origin", origin);
    } else {
        // Fallback for tools without an origin header (like Postman or curl)
        res.setHeader("Access-Control-Allow-Origin", "*");
    }

    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");

    // Must include your specific custom banking/setting tokens
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, Accept, X-Action, X-Action-Phase, X-Transaction-Pin, X-User-UUID, X-Setting-Target, x-setting-target");
    res.setHeader("Access-Control-Allow-Credentials", "true");

    // Handle Preflight checks instantly
    if (req.method === "OPTIONS") {
        res.status(200).end();
        return true;
    }
    return false;
}

export default async function handler(req, res) {
    if (applyCors(req, res)) return;

    // Safe payload parsing to avoid crashing if body parameters arrive null or undefined
    const signature = req.query.signature || (req.body && req.body.signature) || req.headers["x-setting-target"];

    if (!signature) {
        return res.status(400).json({ success: false, error: "Identification environment target footprint signature required." });
    }

    // -------------------------------------------------------------------------
    // METHOD ACTION 1: POST (UPDATE AGREEMENT MATRIX VALUE TO TRUE)
    // -------------------------------------------------------------------------
    if (req.method === "POST") {
        try {
            const { data: updatedRow, error: updateError } = await supabase
                .from("admin")
                .update({ agreement: true })
                .eq("signature", signature.trim())
                .select("agreement")
                .maybeSingle();

            if (updateError) throw updateError;

            return res.status(200).json({
                success: true,
                message: "Administrative agreement legal matrices synchronized successfully.",
                agreement: true
            });
        } catch (err) {
            console.error("❌ CRITICAL INFRASTRUCTURE AGREEMENT WRITE EXCEPTION:", err.message);
            return res.status(500).json({ success: false, error: "Database transaction update fault encountered." });
        }
    }

    // -------------------------------------------------------------------------
    // METHOD ACTION 2: GET (CHECK VISIBILITY, AGREEMENT, EMAIL & ADDRESS)
    // -------------------------------------------------------------------------
    if (req.method === "GET") {
        try {
            // Explicitly select website_visibility, agreement, smtp_email, and address fields
            const { data: adminRow, error: dbError } = await supabase
                .from("admin")
                .select("website_visibility, agreement, smtp_email, address")
                .eq("signature", signature.trim())
                .maybeSingle();

            if (dbError) throw dbError;

            if (!adminRow) {
                return res.status(200).json({
                    success: true,
                    visibility: true,
                    agreement: true, // Default fail-open to preserve client access 
                    adminEmail: null,
                    adminAddress: null,
                    message: "No configuration footprint matched signatures. Open bypass active."
                });
            }

            const isVisible = adminRow.website_visibility === true;

            return res.status(200).json({
                success: true,
                visibility: isVisible,
                agreement: adminRow.agreement === true,
                // Return variables to the frontend only if the website is marked visible
                adminEmail: isVisible ? (adminRow.smtp_email || null) : null,
                adminAddress: isVisible ? (adminRow.address || null) : null
            });

        } catch (err) {
            console.error("❌ CRITICAL INFRASTRUCTURE CORE STATUS CHECK EXCEPTION:", err.message);
            return res.status(500).json({
                success: false,
                visibility: true,
                agreement: true,
                adminEmail: null,
                adminAddress: null,
                error: "Internal database interface query connectivity fault."
            });
        }
    }

    // Fallback block configuration for unknown or unsupported HTTP verbs
    return res.status(405).json({ success: false, error: "Method blocked." });
}