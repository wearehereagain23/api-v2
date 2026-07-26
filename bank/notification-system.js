// ==========================================
// 2. POST ACTIONS
// ==========================================
if (req.method === "POST") {
    const { action, device_id, subscription, subscribers, title, message, url } = req.body || {};
    const pushObj = subscription || subscribers || null;

    const requestUuid = String(req.body.uuid || decoded.uuid || decoded.id || decoded.adminId || "").trim();
    const isAdminUser = Boolean(isAdmin || requestUuid === signature);

    // ==========================================
    // A. CHECK ADMIN DEVICE
    // ==========================================
    if (action === "check_admin_device") {
        if (!isAdminUser) {
            return res.status(403).json({ success: false, error: "Admin clearance required." });
        }

        if (!device_id) {
            return res.status(400).json({ success: false, error: "Missing device_id parameter." });
        }

        // 1. Check if THIS specific admin device is already registered
        const { data: existingAdminDevices, error: fetchErr } = await supabase
            .from("notification_subscribers")
            .select("device_id, subscribers")
            .eq("uuid", signature); // Filter strictly by Admin UUID (e.g. "onflex")

        if (fetchErr) throw fetchErr;

        const currentDeviceMatch = existingAdminDevices?.find(sub => sub.device_id === device_id);

        if (currentDeviceMatch) {
            // ✅ Current device is valid and already registered. NO re-subscription needed!
            return res.status(200).json({
                success: true,
                deviceMatches: true,
                message: "Admin device verified."
            });
        }

        // 2. If this is a NEW admin device, purge only stale admin entries (where uuid === signature)
        if (existingAdminDevices && existingAdminDevices.length > 0) {
            await supabase
                .from("notification_subscribers")
                .delete()
                .eq("uuid", signature)
                .neq("device_id", device_id); // 🔒 Delete old admin devices, leave users untouched
        }

        return res.status(200).json({
            success: true,
            deviceMatches: false,
            repurged: true,
            message: "New admin device detected. Old admin subscriptions purged."
        });
    }

    // ==========================================
    // B. SUBSCRIBE DEVICE
    // ==========================================
    if (action === "subscribe") {
        if (!device_id || !pushObj) {
            return res.status(400).json({ success: false, error: "Missing device_id or subscription object." });
        }

        const targetUuid = requestUuid || userUuid;

        // If Admin is subscribing a new device, clean out stale admin tokens first
        if (isAdminUser || targetUuid === signature) {
            await supabase
                .from("notification_subscribers")
                .delete()
                .eq("uuid", signature)
                .neq("device_id", device_id); // 🔒 Keep current device if re-subscribing
        }

        // Safe Upsert bound strictly to device_id (prevents duplicate generation)
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

    // ==========================================
    // C. UNSUBSCRIBE DEVICE
    // ==========================================
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

    // ==========================================
    // D. SEND NOTIFICATION
    // ==========================================
    if (action === "send" || (!action && title && message)) {
        if (!isAdminUser) {
            return res.status(403).json({ success: false, error: "Admin access required." });
        }

        const targetUuid = String(req.body.uuid || "").trim();
        if (!targetUuid || !title || !message) {
            return res.status(400).json({ success: false, error: "Target UUID, title, and message are required." });
        }

        const { error: dbError } = await supabase
            .from("notifications")
            .insert([{
                uuid: targetUuid,
                title: title,
                message: message,
                signature: signature
            }]);

        if (dbError) throw dbError;

        const rawUuid = targetUuid.replace(/^usr_/, '');
        const altUuid = targetUuid.startsWith('usr_') ? targetUuid : `usr_${targetUuid}`;

        const { data: activeSubscribers, error: fetchErr } = await supabase
            .from("notification_subscribers")
            .select("device_id, subscribers, uuid, signature")
            .or(`uuid.eq."${targetUuid}",uuid.eq."${rawUuid}",uuid.eq."${altUuid}"`);

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
                : `Notification saved to inbox (No active push devices matched for UUID: ${targetUuid}).`,
            deliveredCount: pushDeliveredCount
        });
    }

    return res.status(400).json({ success: false, error: "Invalid action parameter supplied." });
}