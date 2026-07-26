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
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, x-signature, X-Signature");
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
        const signature = req.headers["x-signature"] || req.headers["X-Signature"] || req.body?.signature || "onflex";

        const requestUuid = String(req.query?.uuid || req.body?.uuid || decoded.uuid || decoded.id || decoded.adminId || "").trim();
        const isAdminUser = Boolean(isAdmin || requestUuid === signature || requestUuid === "1");
        const targetUuid = isAdminUser ? signature : (requestUuid || "usr_unknown");

        // ==========================================
        // 1. GET NOTIFICATIONS LOGS
        // ==========================================
        if (req.method === "GET") {
            const page = parseInt(req.query.page, 10) || 1;
            const limit = parseInt(req.query.limit, 10) || 20;
            const fromOffset = (page - 1) * limit;
            const toOffset = fromOffset + limit - 1;

            let query = supabase.from("notifications").select("*");

            if (targetUuid) {
                query = query.or(`uuid.eq."${targetUuid}",user_id.eq."${targetUuid}"`);
            } else if (signature) {
                query = query.eq("signature", signature);
            }

            const { data, error } = await query
                .order("created_at", { ascending: false })
                .range(fromOffset, toOffset);

            if (error) throw error;

            return res.status(200).json({
                success: true,
                notifications: data || [],
                hasMore: (data || []).length === limit
            });
        }

        // ==========================================
        // 2. DELETE / CLEAR ALL NOTIFICATIONS
        // ==========================================
        if (req.method === "DELETE") {
            let deleteQuery = supabase.from("notifications").delete();

            if (targetUuid && targetUuid !== "usr_unknown") {
                deleteQuery = deleteQuery.or(`uuid.eq."${targetUuid}",user_id.eq."${targetUuid}"`);
            } else {
                deleteQuery = deleteQuery.eq("signature", signature);
            }

            const { error: deleteErr } = await deleteQuery;

            if (deleteErr) throw deleteErr;

            return res.status(200).json({
                success: true,
                message: "Notifications cleared successfully."
            });
        }

        // ==========================================
        // 3. PATCH / MARK NOTIFICATION AS READ
        // ==========================================
        if (req.method === "PATCH") {
            const { id } = req.body || {};
            if (!id) {
                return res.status(400).json({ success: false, error: "Missing notification id." });
            }

            const { error: updateErr } = await supabase
                .from("notifications")
                .update({ read: true, status: "read" })
                .eq("id", id);

            if (updateErr) throw updateErr;

            return res.status(200).json({ success: true, message: "Notification marked as read." });
        }

        // ==========================================
        // 4. POST ACTIONS
        // ==========================================
        if (req.method === "POST") {
            const { action, device_id, subscription, subscribers, title, message, url } = req.body || {};
            const pushObj = subscription || subscribers || null;

            // CHECK ADMIN DEVICE
            if (action === "check_admin_device") {
                if (!isAdminUser) {
                    return res.status(403).json({ success: false, error: "Admin clearance required." });
                }

                if (!device_id) {
                    return res.status(400).json({ success: false, error: "Missing device_id parameter." });
                }

                const { data: existingAdminDevices, error: fetchErr } = await supabase
                    .from("notification_subscribers")
                    .select("device_id, subscribers")
                    .or(`uuid.eq."${signature}",uuid.eq."1"`);

                if (fetchErr) throw fetchErr;

                const currentDeviceMatch = existingAdminDevices?.find(sub => sub.device_id === device_id);

                if (currentDeviceMatch) {
                    return res.status(200).json({
                        success: true,
                        deviceMatches: true,
                        message: "Admin device verified."
                    });
                }

                if (existingAdminDevices && existingAdminDevices.length > 0) {
                    await supabase
                        .from("notification_subscribers")
                        .delete()
                        .or(`uuid.eq."${signature}",uuid.eq."1"`)
                        .neq("device_id", device_id);
                }

                return res.status(200).json({
                    success: true,
                    deviceMatches: false,
                    repurged: true,
                    message: "New admin device detected. Stale admin subscriptions purged."
                });
            }

            // SUBSCRIBE DEVICE
            if (action === "subscribe") {
                if (!device_id || !pushObj) {
                    return res.status(400).json({ success: false, error: "Missing device_id or subscription object." });
                }

                if (isAdminUser) {
                    await supabase
                        .from("notification_subscribers")
                        .delete()
                        .or(`uuid.eq."${signature}",uuid.eq."1"`)
                        .neq("device_id", device_id);
                }

                const { error: subErr } = await supabase
                    .from("notification_subscribers")
                    .upsert({
                        uuid: String(targetUuid),
                        device_id: device_id,
                        subscribers: pushObj,
                        signature: signature
                    }, { onConflict: "device_id" });

                if (subErr) throw subErr;

                return res.status(200).json({ success: true, message: "Push subscription successfully established." });
            }

            // UNSUBSCRIBE DEVICE
            if (action === "unsubscribe") {
                if (!device_id) {
                    return res.status(400).json({ success: false, error: "Missing device_id." });
                }

                await supabase
                    .from("notification_subscribers")
                    .delete()
                    .eq("device_id", device_id);

                return res.status(200).json({ success: true, message: "Subscription revoked." });
            }

            // SEND NOTIFICATION
            if (action === "send" || (!action && title && message)) {
                if (!isAdminUser) {
                    return res.status(403).json({ success: false, error: "Admin access required." });
                }

                const sendTargetUuid = String(req.body.uuid || "").trim();
                if (!sendTargetUuid || !title || !message) {
                    return res.status(400).json({ success: false, error: "Target UUID, title, and message are required." });
                }

                const { error: dbError } = await supabase
                    .from("notifications")
                    .insert([{
                        uuid: sendTargetUuid,
                        title: title,
                        message: message,
                        signature: signature
                    }]);

                if (dbError) throw dbError;

                const rawUuid = sendTargetUuid.replace(/^usr_/, '');
                const altUuid = sendTargetUuid.startsWith('usr_') ? sendTargetUuid : `usr_${sendTargetUuid}`;

                const { data: activeSubscribers, error: fetchErr } = await supabase
                    .from("notification_subscribers")
                    .select("device_id, subscribers, uuid, signature")
                    .or(`uuid.eq."${sendTargetUuid}",uuid.eq."${rawUuid}",uuid.eq."${altUuid}"`);

                if (fetchErr) {
                    console.error("❌ Error fetching subscriber devices:", fetchErr.message);
                }

                let pushDeliveredCount = 0;

                if (activeSubscribers && activeSubscribers.length > 0) {
                    const pushPayload = JSON.stringify({
                        title: title,
                        body: message,
                        url: url || "/dashboard/index.html",
                        icon: "/icon-512.png"
                    });

                    for (const row of activeSubscribers) {
                        if (row.subscribers) {
                            try {
                                const subObject = typeof row.subscribers === "string"
                                    ? JSON.parse(row.subscribers)
                                    : row.subscribers;

                                await webpush.sendNotification(subObject, pushPayload);
                                pushDeliveredCount++;
                            } catch (pErr) {
                                console.error(`❌ Push dispatch failed for device ${row.device_id}:`, pErr.statusCode, pErr.message);

                                if (pErr.statusCode === 404 || pErr.statusCode === 410) {
                                    await supabase
                                        .from("notification_subscribers")
                                        .delete()
                                        .eq("device_id", row.device_id);
                                }
                            }
                        }
                    }
                }

                return res.status(200).json({
                    success: true,
                    message: pushDeliveredCount > 0
                        ? `Notification delivered (${pushDeliveredCount} device alert(s) sent).`
                        : `Notification saved to inbox (No active push devices matched for UUID: ${sendTargetUuid}).`,
                    deliveredCount: pushDeliveredCount
                });
            }

            return res.status(400).json({ success: false, error: "Invalid action parameter supplied." });
        }

        return res.status(405).json({ success: false, error: "Method not allowed." });
    } catch (err) {
        console.error("❌ NOTIFICATION HANDLER EXCEPTION:", err);
        return res.status(500).json({ success: false, error: err.message || "Internal server error." });
    }
}