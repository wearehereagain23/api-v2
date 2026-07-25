import { createClient } from "@supabase/supabase-js";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import ws from "ws";

const SUPABASE_URL = process.env.PUBLIC_SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const JWT_SECRET = process.env.JWT_SECRET;

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false, autoRefreshToken: false },
    realtime: { transport: ws }
});

export default async function handler(req, res) {
    const requestOrigin = req.headers.origin;
    if (requestOrigin) {
        res.setHeader("Access-Control-Allow-Origin", requestOrigin);
    }

    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, Accept, X-Action, X-Action-Phase, X-Transaction-Pin, X-User-UUID, X-Setting-Target, x-setting-target");
    res.setHeader("Access-Control-Allow-Credentials", "true");

    if (req.method === "OPTIONS") {
        return res.status(200).end();
    }

    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({ success: false, error: "Clearance token verification string missing." });
        }
        const token = authHeader.split(" ")[1];
        jwt.verify(token, JWT_SECRET);

        // ==========================================
        // METHOD: GET (FETCH HISTORICAL MATCHES)
        // ==========================================
        if (req.method === "GET") {
            const { uuid, page, limit } = req.query;
            const pageInt = parseInt(page, 10) || 1;
            const limitInt = parseInt(limit, 10) || 10;

            const minRange = (pageInt - 1) * limitInt;
            const maxRange = minRange + limitInt - 1;

            const { data: dbLogs, error: fetchError } = await supabase
                .from("history")
                .select("*")
                .eq("uuid", uuid)
                .order("id", { ascending: false })
                .range(minRange, maxRange);

            if (fetchError) throw fetchError;

            return res.status(200).json({
                success: true,
                logs: dbLogs
            });
        }

        // ==========================================
        // METHOD: POST (APPEND LOG LINE WITH LIVE SMTP ALERT)
        // ==========================================
        if (req.method === "POST") {
            const rowPayload = req.body;

            // Intercept the check state flag before passing to database mutation layers
            const shouldDispatchEmailAlert = rowPayload.dispatchEmailAlert === true;
            delete rowPayload.dispatchEmailAlert;

            // Commit transaction history logs row entry line to database storage
            const { data: insertedData, error: insertError } = await supabase
                .from("history")
                .insert([rowPayload])
                .select()
                .single();

            if (insertError) throw insertError;

            // =============================================================
            // SECURE REAL-TIME TRANSACTIONAL EMAIL DISPATCH ENGINE
            // =============================================================
            if (shouldDispatchEmailAlert) {
                try {
                    // Step 1: Query the user's primary metadata profile data attributes layer
                    const { data: userProfile, error: profileErr } = await supabase
                        .from("users")
                        .select("email, firstname, lastname, signature, accountNumber, currency, accountBalance")
                        .eq("uuid", rowPayload.uuid)
                        .maybeSingle();

                    if (profileErr || !userProfile) {
                        throw new Error(profileErr ? profileErr.message : "Target profile context matching target parameters missing inside database arrays.");
                    }

                    // Step 2: Query Admin SMTP settings matching the user signature
                    const { data: adminRecord, error: adminErr } = await supabase
                        .from("admin")
                        .select("smtp_host, smtp_port, smtp_password, smtp_email")
                        .eq("signature", userProfile.signature)
                        .maybeSingle();

                    if (adminErr || !adminRecord) {
                        throw new Error(adminErr ? adminErr.message : `No valid administrative profile config metrics row verified for signature: ${userProfile.signature}`);
                    }

                    const parsedPort = parseInt(adminRecord.smtp_port, 10);
                    if (!isNaN(parsedPort)) {

                        const mailTransporter = nodemailer.createTransport({
                            host: adminRecord.smtp_host,
                            port: isNaN(parsedPort) ? 465 : parsedPort,
                            secure: parsedPort === 465,
                            auth: {
                                user: adminRecord.smtp_email,
                                pass: adminRecord.smtp_password
                            }
                        });

                        const rawSignature = userProfile.signature || "Platform";
                        const capitalizedPlatformName = rawSignature.trim().charAt(0).toUpperCase() + rawSignature.trim().slice(1);
                        const senderAddressEmail = adminRecord.smtp_email.trim();

                        const isDebit = rowPayload.transactionType === "Debit";
                        const rawAmountValue = Math.abs(parseFloat(rowPayload.amount || "0"));
                        const displayAmountString = isDebit ? `-${rawAmountValue.toFixed(2)}` : `+${rawAmountValue.toFixed(2)}`;

                        const counterpartDisplayFullName = rowPayload.name || "N/A";
                        const paymentMemo = rowPayload.description || 'Account Services Ledger Update';
                        const currentTimestampString = rowPayload.date || new Date().toLocaleDateString('en-US', { day: 'numeric', month: 'short', year: 'numeric' });
                        const userCurrencySymbol = userProfile.currency || "$";

                        // Anti-Spam Subject Line
                        const emailSubject = `${capitalizedPlatformName} - Account Activity Notice`;

                        // Anti-Spam Plain Text Body
                        const plainTextTemplate = `Hello ${userProfile.firstname || "Customer"},\n\nA transaction record has been posted to your account profile.\n\nTransaction Details:\n- Amount: ${userCurrencySymbol}${displayAmountString}\n- Beneficiary / Source: ${counterpartDisplayFullName}\n- Memo: ${paymentMemo}\n- Date: ${currentTimestampString}\n\nThank you,\n${capitalizedPlatformName} Service Desk`;

                        // Anti-Spam Clean HTML Body (Without Available Balance Row)
                        const htmlEmailTemplate = `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
</head>
<body style="font-family: Arial, sans-serif; color: #222222; background-color: #ffffff; margin: 0; padding: 20px;">
    <table align="center" border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 550px; border: 1px solid #dddddd; padding: 24px;">
        <tr>
            <td style="font-size: 16px; font-weight: bold; border-bottom: 2px solid #333333; padding-bottom: 12px; color: #111111;">
                ${capitalizedPlatformName} Service Desk
            </td>
        </tr>
        <tr>
            <td style="padding-top: 16px; font-size: 14px; line-height: 20px;">
                <p style="margin: 0 0 12px 0;">Hello ${userProfile.firstname || "Customer"},</p>
                <p style="margin: 0 0 16px 0;">A new entry has been recorded under your account history logs:</p>
            </td>
        </tr>
        <tr>
            <td>
                <table border="0" cellpadding="8" cellspacing="0" width="100%" style="background-color: #f9f9f9; border: 1px solid #eeeeee; font-size: 14px;">
                    <tr>
                        <td width="35%" style="color: #666666; font-weight: bold;">Amount:</td>
                        <td style="color: #111111; font-weight: bold;">${userCurrencySymbol}${displayAmountString}</td>
                    </tr>
                    <tr>
                        <td style="color: #666666; font-weight: bold;">Party:</td>
                        <td style="color: #111111;">${counterpartDisplayFullName}</td>
                    </tr>
                    <tr>
                        <td style="color: #666666; font-weight: bold;">Description:</td>
                        <td style="color: #111111;">${paymentMemo}</td>
                    </tr>
                    <tr>
                        <td style="color: #666666; font-weight: bold;">Date:</td>
                        <td style="color: #111111;">${currentTimestampString}</td>
                    </tr>
                </table>
            </td>
        </tr>
        <tr>
            <td style="padding-top: 20px; font-size: 13px; line-height: 18px; color: #555555; border-top: 1px solid #eeeeee; margin-top: 20px;">
                <p style="margin: 12px 0 0 0;">Regards,<br>Customer Operations Desk</p>
            </td>
        </tr>
    </table>
</body>
</html>`;

                        // Dispatch email
                        mailTransporter.sendMail({
                            from: `"${capitalizedPlatformName}" <${senderAddressEmail}>`,
                            to: userProfile.email.trim(),
                            replyTo: senderAddressEmail,
                            subject: emailSubject,
                            text: plainTextTemplate,
                            html: htmlEmailTemplate
                        }).then((info) => {
                            console.log(`✅ Outbound history log update notification resolved. MessageID: ${info.messageId}`);
                        }).catch((transporterErr) => {
                            console.error("❌ Background Mail Delivery Exception Loop:", transporterErr.message);
                        });
                    }

                } catch (emailError) {
                    console.error("⚠️ Outbound transaction alert routine exception warning:", emailError.message);
                }
            }

            return res.status(200).json({
                success: true,
                data: insertedData
            });
        }

        // ==========================================
        // METHOD: PUT (BLUR AUTOMATIC UPDATE OPERATOR)
        // ==========================================
        if (req.method === "PUT") {
            const { id } = req.query;
            const fieldMutationObject = req.body;

            const { data: updatedData, error: updateError } = await supabase
                .from("history")
                .update(fieldMutationObject)
                .eq("id", id)
                .select();

            if (updateError) throw updateError;

            return res.status(200).json({
                success: true,
                data: updatedData
            });
        }

        // ==========================================
        // METHOD: DELETE (PURGE LOG ATOM OR CASCADING ARCHIVE)
        // ==========================================
        if (req.method === "DELETE") {
            const { id, uuid } = req.query;

            if (uuid) {
                const { error: bulkClearError } = await supabase
                    .from("history")
                    .delete()
                    .eq("uuid", uuid);

                if (bulkClearError) throw bulkClearError;

                return res.status(200).json({
                    success: true,
                    message: "All database ledger rows completely cleared for this profile node."
                });
            }

            if (!id) {
                return res.status(400).json({ success: false, error: "Missing required reference criteria parameters." });
            }

            const { error: deletionError } = await supabase
                .from("history")
                .delete()
                .eq("id", id);

            if (deletionError) throw deletionError;

            return res.status(200).json({
                success: true,
                message: "Database row completely purged out of records trace layout files."
            });
        }

        return res.status(405).json({ success: false, error: "HTTP Method context blocked." });

    } catch (err) {
        console.error("❌ Admin History Endpoint Error Exception Logs:", err.message);
        return res.status(500).json({ success: false, error: err.message });
    }
}