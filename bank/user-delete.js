import { createClient } from "@supabase/supabase-js";
import jwt from "jsonwebtoken";
import ws from "ws";
import nodemailer from "nodemailer";

const SUPABASE_URL = process.env.PUBLIC_SUPABASE_URL || process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY;
const JWT_SECRET = process.env.JWT_SECRET;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY || !JWT_SECRET) {
    throw new Error("CRITICAL CONFIGURATION ERROR: Supabase or JWT credential mappings are unassigned.");
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false },
    realtime: { transport: ws }
});

/**
 * Controller Route Handler for User Account Termination
 */
export default async function deleteAccountHandler(req, res) {
    const requestOrigin = req.headers.origin;
    if (requestOrigin) res.setHeader("Access-Control-Allow-Origin", requestOrigin);
    res.setHeader("Access-Control-Allow-Methods", "DELETE, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

    if (req.method === "OPTIONS") return res.status(200).end();
    if (req.method !== "DELETE") return res.status(405).json({ success: false, error: "Method blocked." });

    // Authorization Header Check
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

    const { signature } = req.body || {};
    if (!signature) {
        return res.status(400).json({ success: false, error: "Invalid or missing confirmation signature." });
    }

    try {
        // 1. Fetch user data before deletion (needed for email notification)
        const { data: userData, error: userFetchError } = await supabase
            .from("users")
            .select("email, fullname, first_name, last_name")
            .eq("uuid", verifiedUuid)
            .single();

        if (userFetchError || !userData) {
            console.warn("⚠️ Could not fetch user data for deletion email notification:", userFetchError?.message);
        }

        const userEmail = userData?.email;
        const userName = userData?.fullname || `${userData?.first_name || ''} ${userData?.last_name || ''}`.trim() || "Valued User";

        // 2. Fetch SMTP configurations and Admin Email settings from 'admin' table
        const { data: adminConfig } = await supabase
            .from("admin")
            .select("smtp_host, smtp_port, smtp_user, smtp_pass, admin_email, company_name")
            .eq("id", 1)
            .single();

        // 3. Cascade Delete User Records across database tables
        const tables = ['chats', 'notifications', 'notification_subscribers', 'history', 'devices', 'users'];

        for (const table of tables) {
            const { error } = await supabase.from(table).delete().eq('uuid', verifiedUuid);
            if (error) {
                console.warn(`⚠️ Could not delete user records from table '${table}':`, error.message);
            }
        }

        // 4. Dispatch Email Notifications if SMTP configuration exists
        if (adminConfig && adminConfig.smtp_host && adminConfig.smtp_user) {
            try {
                const transporter = nodemailer.createTransport({
                    host: adminConfig.smtp_host,
                    port: parseInt(adminConfig.smtp_port) || 587,
                    secure: parseInt(adminConfig.smtp_port) === 465,
                    auth: {
                        user: adminConfig.smtp_user,
                        pass: adminConfig.smtp_pass
                    }
                });

                const companyName = adminConfig.company_name || "ONFLEX";
                const adminEmail = adminConfig.admin_email || adminConfig.smtp_user;

                // --- Goodbye Email to User ---
                if (userEmail) {
                    const userMailOptions = {
                        from: `"${companyName}" <${adminConfig.smtp_user}>`,
                        to: userEmail,
                        subject: `Account Terminated - ${companyName}`,
                        html: `
                            <div style="font-family: Arial, sans-serif; background-color: #0c1e29; color: #ffffff; padding: 20px; border-radius: 8px;">
                                <h2 style="color: #ef4444;">Account Closed</h2>
                                <p>Dear <strong>${userName}</strong>,</p>
                                <p>This email confirms that your account and all associated data have been permanently deleted from our system as requested.</p>
                                <p>If you did not authorize this action, please contact our support team immediately.</p>
                                <br />
                                <p style="font-size: 12px; color: #94a3b8;">Thank you for using ${companyName}.</p>
                            </div>
                        `
                    };
                    await transporter.sendMail(userMailOptions);
                }

                // --- Alert Email to Admin ---
                if (adminEmail) {
                    const adminMailOptions = {
                        from: `"${companyName} System" <${adminConfig.smtp_user}>`,
                        to: adminEmail,
                        subject: `[SYSTEM ALERT] Account Deleted - ${userName}`,
                        html: `
                            <div style="font-family: Arial, sans-serif; background-color: #0c1e29; color: #ffffff; padding: 20px; border-radius: 8px;">
                                <h2 style="color: #f59e0b;">User Account Terminated</h2>
                                <p>A user account has been completely wiped and removed from the system.</p>
                                <ul>
                                    <li><strong>User Name:</strong> ${userName}</li>
                                    <li><strong>User Email:</strong> ${userEmail || 'N/A'}</li>
                                    <li><strong>User UUID:</strong> ${verifiedUuid}</li>
                                    <li><strong>Signature Provided:</strong> ${signature}</li>
                                    <li><strong>Timestamp:</strong> ${new Date().toISOString()}</li>
                                </ul>
                            </div>
                        `
                    };
                    await transporter.sendMail(adminMailOptions);
                }

            } catch (mailError) {
                console.error("❌ Failed to dispatch deletion emails via Nodemailer:", mailError);
            }
        }

        return res.status(200).json({
            success: true,
            message: "Account and associated user records deleted successfully."
        });

    } catch (globalFault) {
        console.error("❌ Global transaction failure on account deletion:", globalFault);
        return res.status(500).json({
            success: false,
            error: globalFault.message || "Internal database network fault during deletion."
        });
    }
}