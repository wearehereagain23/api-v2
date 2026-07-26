import { createClient } from "@supabase/supabase-js";
import jwt from "jsonwebtoken";
import ws from "ws";
import webpush from "web-push";

const SUPABASE_URL = process.env.PUBLIC_SUPABASE_URL || process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY;
const JWT_SECRET = process.env.JWT_SECRET;

const VAPID_PUBLIC_KEY = process.env.PUBLIC_VAPID_KEY || process.env.VAPID_PUBLIC_KEY || "";
const VAPID_PRIVATE_KEY = process.env.PRIVATE_VAPID_KEY || process.env.VAPID_PRIVATE_KEY || "";
const VAPID_SUBJECT = process.env.VAPID_SUBJECT || "mailto:admin@onflex.com";

if (VAPID_PUBLIC_KEY && VAPID_PRIVATE_KEY) {
    webpush.setVapidDetails(VAPID_SUBJECT, VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false },
    realtime: { transport: ws }
});

function applyCors(req, res) {
    const origin = req.headers.origin || "*";
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, x-signature");
    if (req.method === "OPTIONS") {
        res.status(200).end();
        return true;
    }
    return false;
}

export default async function handler(req, res) {
    if (applyCors(req, res)) return;

    const authHeader = req.headers.authorization || req.headers.Authorization || "";
    if (!authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ success: false, error: "Unauthorized access credentials missing." });
    }

    const token = authHeader.split(" ")[1];
    let decoded = null;

    try {
        decoded = jwt.verify(token, JWT_SECRET);
    } catch (jwtErr) {
        return res.status(401).json({ success: false, error: "Session token expired or invalid." });
    }

    try {
        const isAdmin = Boolean(decoded.adminId || decoded.role === "admin" || decoded.isAdmin);
        const resolvedUuid = req.body.uuid || decoded.uuid || decoded.id || decoded.adminId || "admin_root";
        const signature = req.headers["x-signature"] || req.body.signature || "onflex";

        if (req.method === "POST") {
            const { action, device_id, subscription, title, message, url } = req.body;

            // =========================================================================
            // 1. CHECK ADMIN DEVICE & SIGNATURE MATCH EXCLUSIVELY
            // =========================================================================
            if (action === "check_admin_device") {
                if (!isAdmin) {
                    return res.status(403).json({ success: false, error: "Access denied: Not an admin context." });
                }

                // Check existing admin subscription with this signature
                const { data: existingSubs, error: fetchErr } = await supabase
                    .from("notification_subscribers")
                    .select("*")
                    .eq("signature", signature);

                if (fetchErr) throw fetchErr;

                if (existingSubs && existingSubs.length > 0) {
                    const match = existingSubs.find(sub => sub.device_id === device_id);

                    if (match) {
                        return res.status(200).json({
                            success: true,
                            deviceMatches: true,
                            message: "Admin device verified."
                        });
                    } else {
                        // Delete older device subscriptions under this signature
                        await supabase
                            .from("notification_subscribers")
                            .delete()
                            .eq("signature", signature);

                        return res.status(200).json({
                            success: true,
                            deviceMatches: false,
                            repurged: true,
                            message: "Older admin devices purged."
                        });
                    }
                }

                return res.status(200).json({
                    success: true,
                    deviceMatches: false,
                    repurged: false,
                    message: "No registered admin device found for this signature."
                });
            }

            // =========================================================================
            // 2. SUBSCRIBE / UPDATE ADMIN PUSH SUBSCRIPTION
            // =========================================================================
            if (action === "subscribe") {
                if (!device_id || !subscription) {
                    return res.status(400).json({ success: false, error: "Missing device_id or subscription parameters." });
                }

                // Remove existing records with this signature to ensure only ONE active admin
                if (isAdmin) {
                    await supabase
                        .from("notification_subscribers")
                        .delete()
                        .eq("signature", signature);
                }

                // Standard user subscription: keeps all user devices intact per signature
                const { error: subErr } = await supabase
                    .from("notification_subscribers")
                    .upsert({
                        uuid: String(resolvedUuid),
                        device_id: device_id,
                        subscribers: pushObj,
                        signature: signature
                    }, { onConflict: "device_id" });

                if (subErr) throw subErr;

                return res.status(200).json({ success: true, message: "Push subscription successfully established." });
            }

            // =========================================================================
            // 3. DISPATCH NOTIFICATION
            // =========================================================================
            if (action === "send") {
                if (!isAdmin) {
                    return res.status(403).json({ success: false, error: "Admin access required." });
                }

                const targetUuid = req.body.uuid;
                if (!targetUuid || !title || !message) {
                    return res.status(400).json({ success: false, error: "Target UUID, title, and message are required." });
                }

                await supabase.from("notifications").insert([{
                    uuid: targetUuid,
                    title: title,
                    message: message,
                    signature: signature
                }]);

                const { data: subscribers } = await supabase
                    .from("notification_subscribers")
                    .select("device_id, subscribers")
                    .eq("uuid", targetUuid);

                if (subscribers && subscribers.length > 0) {
                    const pushPayload = JSON.stringify({
                        title: title,
                        body: message,
                        url: url || "dashboard/index.html"
                    });

                    for (const row of subscribers) {
                        if (row.subscribers) {
                            try {
                                await webpush.sendNotification(row.subscribers, pushPayload);
                            } catch (err) {
                                if (err.statusCode === 404 || err.statusCode === 410) {
                                    await supabase.from("notification_subscribers").delete().eq("device_id", row.device_id);
                                }
                            }
                        }
                    }
                }

                return res.status(200).json({ success: true, message: "Notification dispatched successfully." });
            }
        }

        return res.status(405).json({ success: false, error: "Method not allowed." });
    } catch (err) {
        console.error("❌ Notification Server Error:", err.message);
        return res.status(500).json({ success: false, error: err.message || "Internal server error." });
    }
}