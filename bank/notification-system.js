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
} else {
    console.warn("⚠️ [WebPush Warning]: VAPID keys are missing from environment variables.");
}

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY || !JWT_SECRET) {
    throw new Error("CRITICAL SYSTEM CONFIGURATION FAULT: Environment matrix variables missing.");
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false, autoRefreshToken: false },
    realtime: { transport: ws }
});

function applyCors(req, res) {
    const origin = req.headers.origin;
    if (origin) {
        res.setHeader("Access-Control-Allow-Origin", origin);
    } else {
        res.setHeader("Access-Control-Allow-Origin", "*");
    }
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, Accept, X-Signature, x-signature, X-User-UUID, x-user-uuid");
    res.setHeader("Access-Control-Allow-Credentials", "true");

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
        return res.status(401).json({
            success: false,
            error: "Your user login session has expired or token signature is corrupt."
        });
    }

    try {
        const isAdmin = Boolean(decoded.adminId || decoded.role === "admin" || decoded.isAdmin);
        const userUuid = req.query.uuid || req.body.uuid || decoded.uuid || decoded.id;
        const userSignature = req.headers["x-signature"] || req.headers["X-Signature"] || decoded.signature;

        let signatureToFilter = userSignature;
        if (!signatureToFilter && userUuid) {
            const { data: userProfile } = await supabase
                .from("users")
                .select("signature")
                .or(`uuid.eq.${userUuid},id.eq.${userUuid}`)
                .maybeSingle();

            if (userProfile) {
                signatureToFilter = userProfile.signature;
            }
        }

        // =========================================================================
        // 1. GET NOTIFICATIONS: Filtered by signature / user UUID with Pagination
        // =========================================================================
        if (req.method === "GET") {
            const page = parseInt(req.query.page, 10) || 1;
            const limit = parseInt(req.query.limit, 10) || 20;
            const fromOffset = (page - 1) * limit;
            const toOffset = fromOffset + limit - 1;

            let query = supabase.from("notifications").select("*");

            if (signatureToFilter) {
                query = query.eq("signature", signatureToFilter);
            } else if (userUuid) {
                query = query.eq("uuid", userUuid);
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

        // =========================================================================
        // 2. POST: SUBSCRIBE, UNSUBSCRIBE & ADMIN NOTIFICATION DISPATCH
        // =========================================================================
        if (req.method === "POST") {
            const { action, title, message, url, device_id, subscription } = req.body;

            // --- A. SUBSCRIBE DEVICE ---
            if (action === "subscribe") {
                if (!device_id || !subscription) {
                    return res.status(400).json({ success: false, error: "Missing subscription details." });
                }

                const targetUuid = req.body.uuid || userUuid || "1";

                const { error: subErr } = await supabase
                    .from("notification_subscribers")
                    .upsert({
                        uuid: targetUuid,
                        device_id: device_id,
                        subscribers: subscription
                    }, { onConflict: "device_id" });

                if (subErr) throw subErr;

                return res.status(200).json({ success: true, message: "Push subscription registered." });
            }

            // --- B. UNSUBSCRIBE DEVICE ---
            if (action === "unsubscribe") {
                if (!device_id) {
                    return res.status(400).json({ success: false, error: "Missing device identification parameter." });
                }

                const { error: unsubErr } = await supabase
                    .from("notification_subscribers")
                    .delete()
                    .eq("device_id", device_id);

                if (unsubErr) throw unsubErr;

                return res.status(200).json({ success: true, message: "Push subscription removed." });
            }

            // --- C. DISPATCH NOTIFICATION (ADMIN ONLY) ---
            if (action === "send" || (!action && title && message)) {
                if (!isAdmin) {
                    return res.status(403).json({ success: false, error: "Only administrative users can trigger push notifications." });
                }

                const targetUuid = req.body.uuid || userUuid;
                if (!targetUuid || !title || !message) {
                    return res.status(400).json({ success: false, error: "Target user UUID, title, and message are required." });
                }

                // 1. Insert notification entry into DB inbox
                const notifPayload = {
                    uuid: targetUuid,
                    title: title,
                    message: message
                };
                if (signatureToFilter) notifPayload.signature = signatureToFilter;

                const { error: dbError } = await supabase
                    .from("notifications")
                    .insert([notifPayload]);

                if (dbError) throw dbError;

                // 2. Increment badge counter via RPC procedure if configured
                try {
                    await supabase.rpc("increment_notification_count", { target_uuid: targetUuid });
                } catch (rpcErr) {
                    console.warn("⚠️ Notification count increment RPC failed/bypassed:", rpcErr.message);
                }

                // 3. Web Push Dispatch Execution Logic
                let pushDispatched = false;

                if (VAPID_PRIVATE_KEY) {
                    console.log(`🔍 [PUSH DISPATCH] Searching devices for target UUID: "${targetUuid}"`);

                    const { data: subscribers, error: subErr } = await supabase
                        .from("notification_subscribers")
                        .select("device_id, subscribers")
                        .eq("uuid", targetUuid);

                    if (subErr) {
                        console.error("❌ Error fetching push subscribers:", subErr.message);
                    }

                    console.log(`📱 Found ${subscribers?.length || 0} registered push devices for user ${targetUuid}.`);

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
                                    console.log(`✅ Push notification sent successfully to device: ${row.device_id}`);
                                    pushDispatched = true;
                                } catch (pErr) {
                                    console.error(`❌ Push Error for Device ${row.device_id}:`, pErr.statusCode, pErr.message);

                                    // Automatic cleanup of revoked or expired subscriptions
                                    if (pErr.statusCode === 404 || pErr.statusCode === 410) {
                                        console.log(`🧹 Removing invalid subscription record for device: ${row.device_id}`);
                                        await supabase
                                            .from("notification_subscribers")
                                            .delete()
                                            .eq("device_id", row.device_id);
                                    }
                                }
                            }
                        }
                    }
                } else {
                    console.warn("⚠️ Push dispatch skipped: VAPID_PRIVATE_KEY missing from server configuration.");
                }

                return res.status(200).json({
                    success: true,
                    message: pushDispatched
                        ? "Notification delivered to user inbox and push devices."
                        : "Notification saved to user inbox."
                });
            }

            return res.status(400).json({ success: false, error: "Invalid POST action command parameter." });
        }

        // =========================================================================
        // 3. PATCH: MARK SINGLE OR ALL NOTIFICATIONS AS READ
        // =========================================================================
        if (req.method === "PATCH") {
            const { id, mark_all_read } = req.body;

            if (mark_all_read) {
                let updateQuery = supabase.from("notifications").update({ read: true });
                if (signatureToFilter) {
                    updateQuery = updateQuery.eq("signature", signatureToFilter);
                } else if (userUuid) {
                    updateQuery = updateQuery.eq("uuid", userUuid);
                }

                const { error: markError } = await updateQuery;
                if (markError) throw markError;

                return res.status(200).json({ success: true, message: "All notifications marked as read." });
            }

            if (!id) {
                return res.status(400).json({ success: false, error: "Notification ID required." });
            }

            const { data: updatedNotif, error: updateErr } = await supabase
                .from("notifications")
                .update({ read: true })
                .eq("id", id)
                .select()
                .single();

            if (updateErr) throw updateErr;

            return res.status(200).json({ success: true, notification: updatedNotif });
        }

        // =========================================================================
        // 4. DELETE: CLEAR CURRENT USER NOTIFICATIONS
        // =========================================================================
        if (req.method === "DELETE") {
            const notifId = req.query.id || req.body.id;

            if (notifId) {
                const { error: singleDeleteErr } = await supabase
                    .from("notifications")
                    .delete()
                    .eq("id", notifId);

                if (singleDeleteErr) throw singleDeleteErr;
                return res.status(200).json({ success: true, message: "Notification removed." });
            }

            let purgeQuery = supabase.from("notifications").delete();

            if (signatureToFilter) {
                purgeQuery = purgeQuery.eq("signature", signatureToFilter);
            } else if (userUuid) {
                purgeQuery = purgeQuery.eq("uuid", userUuid);
            } else {
                return res.status(400).json({ success: false, error: "User identity required for clearing logs." });
            }

            const { error: clearAllErr } = await purgeQuery;
            if (clearAllErr) throw clearAllErr;

            return res.status(200).json({ success: true, message: "All user notifications cleared." });
        }

        return res.status(405).json({ success: false, error: "Method not allowed." });

    } catch (err) {
        console.error("❌ NOTIFICATION SYSTEM FAILURE:", err);
        return res.status(500).json({ success: false, error: err.message || "Internal server fault." });
    }
}