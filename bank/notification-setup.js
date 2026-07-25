import { createClient } from "@supabase/supabase-js";
import jwt from "jsonwebtoken";
import ws from "ws";

// Structural Variable Mapping matching core ledger profiles matrix
const SUPABASE_URL = process.env.PUBLIC_SUPABASE_URL || process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY;
const JWT_SECRET = process.env.JWT_SECRET;

// Securely instantiate operational client environment with persistent sessions disabled
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false },
    realtime: { transport: ws }
});

/**
 * Core Controller Route Handler Engine for Push Subscription Actions
 */
export default async function notificationSetupHandler(req, res) {
    // CORS Preflight handshake setup execution
    const requestOrigin = req.headers.origin;
    if (requestOrigin) {
        res.setHeader("Access-Control-Allow-Origin", requestOrigin);
    }
    res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, x-setting-target");

    if (req.method === "OPTIONS") return res.status(200).end();

    // Authentication Context Layer Protection
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ success: false, error: "Access Denied: Auth context missing." });
    }

    const token = authHeader.split(" ")[1];

    try {
        // Decrypt and process JWT Claims identity token packet matrix
        const decodedClaims = jwt.verify(token, JWT_SECRET);
        const verifiedUuid = decodedClaims.uuid || decodedClaims.id || (decodedClaims.user && decodedClaims.user.id);

        if (!verifiedUuid) {
            return res.status(401).json({ success: false, error: "Unauthorized Identity verification status." });
        }

        const { action, uuid, device_id, subscribers, signature } = req.body;

        // Validate corporate application ecosystem parameter signature match bounds
        if (!signature || signature !== "onflex") {
            return res.status(400).json({ success: false, error: "System access vector validation failed." });
        }

        // Verify requesting identity parameter payload matches verified token details
        if (!uuid || !device_id || String(uuid).trim() !== String(verifiedUuid).trim()) {
            return res.status(400).json({ success: false, error: "Required account identity parameters are missing or mismatched." });
        }

        if (action === "subscribe") {
            if (!subscribers) {
                return res.status(400).json({ success: false, error: "Push service registration context mapping missing." });
            }

            // Synchronize database records safely matching schema requirements including signature
            const { error } = await supabase
                .from('notification_subscribers')
                .upsert({
                    uuid: uuid,
                    device_id: device_id,
                    subscribers: subscribers,
                    signature: signature // Map parameter payload explicitly to your db schema column
                }, { onConflict: 'device_id' });

            if (error) throw error;

            return res.status(200).json({ success: true, message: "Device registration synced successfully." });

        } else if (action === "unsubscribe") {
            // Delete subscription trace parameters mapping matching active profile criteria records contexts
            const { error } = await supabase
                .from('notification_subscribers')
                .delete()
                .match({ device_id: device_id, uuid: uuid });

            if (error) throw error;

            return res.status(200).json({ success: true, message: "Device profile credentials removed safely." });

        } else {
            return res.status(400).json({ success: false, error: "Unsupported operation matrix signature parameters." });
        }

    } catch (err) {
        console.error("🚨 [Backend Notification Error]:", err.message);

        if (err.name === "JsonWebTokenError" || err.name === "TokenExpiredError") {
            return res.status(401).json({ success: false, error: "Session token validation dropped or expired." });
        }

        return res.status(500).json({ success: false, error: "Internal processing error occurred while updating system registry states." });
    }
}