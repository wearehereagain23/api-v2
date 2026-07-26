import { createClient } from "@supabase/supabase-js";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import ws from "ws";

const SUPABASE_URL = process.env.PUBLIC_SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const JWT_SECRET = process.env.JWT_SECRET;

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false },
  realtime: { transport: ws }
});

function generateReceiptHtml({
  recipientName,
  transactionType,
  amountText,
  descriptionText,
  partyName,
  balanceText,
  dateString
}) {
  const isCredit = transactionType.toLowerCase() === "credit";
  const amountColor = isCredit ? "#14a24a" : "#dc2626";

  return `
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; max-width: 540px; margin: 30px auto; border: 1px solid #e2e8f0; border-radius: 12px; background-color: #ffffff; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05), 0 2px 4px -1px rgba(0, 0, 0, 0.03); overflow: hidden;">
        <div style="background: #111115; padding: 24px; text-align: center; border-bottom: 3px solid #0a698f;">
            <h2 style="margin: 0; color: #ffffff; font-size: 20px; letter-spacing: 1px;">ONFLEX FINANCE</h2>
            <p style="margin: 4px 0 0 0; color: #888; font-size: 11px; text-transform: uppercase;">Transaction Settlement Docket</p>
        </div>
        <div style="padding: 24px; background: #ffffff;">
            <div style="text-align: center; margin-bottom: 24px;">
                <div style="font-size: 12px; color: #64748b; text-transform: uppercase; font-weight: 600; letter-spacing: 0.5px;">Amount Remitted</div>
                <div style="font-size: 32px; font-weight: 700; color: ${amountColor}; margin: 8px 0;">${amountText}</div>
                <div style="display: inline-block; padding: 4px 12px; background: #f1f5f9; color: #475569; font-size: 11px; border-radius: 20px; font-weight: 500;">SWIFT In-Flight</div>
            </div>
            <div style="border-top: 1px solid #f1f5f9; padding-top: 20px;">
                <table style="width: 100%; border-collapse: collapse; font-size: 13px; color: #334155;">
                    <tr>
                        <td style="padding: 8px 0; color: #64748b;">Recipient Name</td>
                        <td style="padding: 8px 0; text-align: right; font-weight: 600;">${recipientName}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px 0; color: #64748b;">Transaction Type</td>
                        <td style="padding: 8px 0; text-align: right; font-weight: 600;">${transactionType}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px 0; color: #64748b;">Reference Registry</td>
                        <td style="padding: 8px 0; text-align: right; font-family: monospace; font-weight: 600;">${partyName}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px 0; color: #64748b;">Settlement Date</td>
                        <td style="padding: 8px 0; text-align: right;">${dateString}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px 0; color: #64748b;">New Balance</td>
                        <td style="padding: 8px 0; text-align: right; font-weight: 600; color: #0f172a;">${balanceText}</td>
                    </tr>
                </table>
            </div>
            <div style="margin-top: 24px; padding: 12px; background: #f8fafc; border-radius: 8px; font-size: 12px; color: #64748b; line-height: 1.5; border-left: 3px solid #cbd5e1;">
                <strong>Compliance Note:</strong> ${descriptionText}
            </div>
        </div>
        <div style="background: #f8fafc; padding: 16px; text-align: center; border-top: 1px solid #f1f5f9;">
            <p style="margin: 0; font-size: 11px; color: #94a3b8;">© 2026 OnFlex Finance Group. All Rights Reserved.</p>
            <p style="font-size: 11px; color: #888888; margin-top: 6px;">This is an automated notification. Please do not reply directly to this email.</p>
        </div>
    </div>
  `;
}

export default async function handler(req, res) {
  const requestOrigin = req.headers.origin;
  if (requestOrigin) res.setHeader("Access-Control-Allow-Origin", requestOrigin);
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, x-signature, x-action-phase");
  res.setHeader("Access-Control-Allow-Credentials", "true");

  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "POST") return res.status(405).json({ success: false, error: "Method blocked." });

  try {
    // 1. TOKEN AUTHENTICATION
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ success: false, error: "Missing authorization token." });
    }
    const token = authHeader.split(" ")[1];
    let decodedToken;
    try {
      decodedToken = jwt.verify(token, JWT_SECRET);
    } catch (err) {
      return res.status(403).json({ success: false, error: "Invalid or expired token." });
    }
    const authUserId = decodedToken.id || decodedToken.uuid;

    // 2. SIGNATURE VERIFICATION
    const clientSignature = req.headers["x-signature"] || req.headers["X-Signature"];
    if (!clientSignature || clientSignature.toLowerCase() !== "onflex") {
      return res.status(403).json({ success: false, error: "Gateway authentication failed." });
    }

    const clientActionPhase = req.headers["x-action-phase"] || req.headers["X-Action-Phase"];

    // FETCH REUSABLE CURRENT USER PROFILE DATA
    const { data: userData, error: userFetchError } = await supabase
      .from("users")
      .select("*")
      .eq("uuid", authUserId)
      .single();

    if (userFetchError || !userData) {
      return res.status(404).json({ success: false, error: "User profile not found." });
    }

    // BLOCK PRE-EMPTIVELY IF ACCOUNT HAS ALREADY TRIGGERED FULL RESTRICTIONS
    if (userData.restricted === true || userData.block_transection === true) {
      return res.status(403).json({ success: false, error: "Access Revoked. Transaction profile is restricted." });
    }

    // ==========================================
    // COMPLIANCE CODE MULTI-STAGE STEP HANDLING
    // ==========================================
    if (clientActionPhase === "verify-imf" || clientActionPhase === "verify-tax" || clientActionPhase === "verify-cot") {
      const { code } = req.body;
      let targetColumn = "";

      if (clientActionPhase === "verify-imf") targetColumn = "IMF";
      else if (clientActionPhase === "verify-tax") targetColumn = "TAX";
      else if (clientActionPhase === "verify-cot") targetColumn = "COT";

      const databaseCodeValue = userData[targetColumn];

      // Match check
      if (databaseCodeValue && code && databaseCodeValue.trim() === code.trim()) {
        // CODE IS PERFECT: Reset attempt metrics counters back to zero layout
        await supabase
          .from("users")
          .update({ attempt: 0 })
          .eq("uuid", authUserId);

        return res.status(200).json({ success: true, message: `${targetColumn} validation authorized.` });
      } else {
        // CODE IS WRONG: Increment attempt counter array values
        const runningAttempts = (parseInt(userData.attempt) || 0) + 1;
        const triggerLockout = runningAttempts >= 5;

        await supabase
          .from("users")
          .update({
            attempt: runningAttempts,
            restricted: triggerLockout ? true : userData.restricted
          })
          .eq("uuid", authUserId);

        if (triggerLockout) {
          return res.status(403).json({ success: false, error: "Security threshold reached. Account profile restricted." });
        }

        return res.status(400).json({ success: false, error: `Invalid security ${targetColumn} code profile match context.` });
      }
    }

    // ==========================================
    // FAILSAFE FORCE CONTEXT ACCOUNT LOCK ACTION
    // ==========================================
    if (clientActionPhase === "lock-account") {
      await supabase
        .from("users")
        .update({ restricted: true })
        .eq("uuid", authUserId);
      return res.status(200).json({ success: true, message: "Security pipeline profile locked." });
    }

    // ==========================================
    // COMMIT FINAL DIRECT BANK REMITTANCE DISPATCH
    // ==========================================
    if (clientActionPhase === "commit-transfer") {
      const { fullname, bankname, des, amount, balanceSource } = req.body;
      const parsedAmount = parseFloat(amount) || 0;

      const currentBalance = parseFloat(userData[balanceSource] || 0);
      if (parsedAmount > currentBalance) {
        return res.status(400).json({ success: false, error: "Insufficient funds." });
      }

      const updateBalanceValue = currentBalance - parsedAmount;

      const { error: balanceUpdateError } = await supabase
        .from("users")
        .update({ [balanceSource]: updateBalanceValue.toString() })
        .eq("uuid", authUserId);

      if (balanceUpdateError) throw new Error(`Deduction failure: ${balanceUpdateError.message}`);

      const referenceId = `TXN-SWIFT-${Math.floor(100000 + Math.random() * 900000)}`;

      await supabase.from("history").insert([{
        uuid: authUserId,
        title: "SWIFT Outbound Remittance",
        des: des || `Cross-Border Wire Transfer to ${bankname}`,
        amount: `-${parsedAmount.toFixed(2)}`,
        status: "Processing",
        date: new Date().toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })
      }]);

      try {
        const { data: smtpSettings, error: smtpError } = await supabase
          .from("admin")
          .select("*")
          .eq("id", 1)
          .single();

        if (smtpSettings && !smtpError) {
          const mailTransporter = nodemailer.createTransport({
            host: smtpSettings.smtp_host,
            port: smtpSettings.smtp_port,
            auth: {
              user: smtpSettings.smtp_email,
              pass: smtpSettings.smtp_password
            }
          });

          const emailDomain = smtpSettings.smtp_email ? smtpSettings.smtp_email.split("@")[1] : "platform.com";
          const noReplyHeader = `"No-Reply Automated System" <no-reply@${emailDomain}>`;

          const senderSymbol = userData.currency || "$";
          const mailOptions = {
            from: `"OnFlex Finance" <${smtpSettings.smtp_email}>`,
            replyTo: noReplyHeader,
            to: userData.email,
            subject: "Transaction Settlement Docket",
            html: generateReceiptHtml({
              recipientName: `${userData.firstname || ""} ${userData.lastname || ""}`,
              transactionType: "Debit",
              amountText: `-${senderSymbol}${parsedAmount.toFixed(2)}`,
              descriptionText: des || `Cross-Border Wire Transfer to ${bankname}`,
              partyName: referenceId,
              balanceText: `${senderSymbol}${updateBalanceValue.toFixed(2)}`,
              dateString: new Date().toLocaleDateString()
            })
          };

          await mailTransporter.sendMail(mailOptions);
          console.log("📨 Email dispatched successfully to:", userData.email);
        } else {
          console.error("SMTP Config not found or invalid:", smtpError);
        }
      } catch (e) {
        console.error("SMTP Delivery Failed:", e.message);
      }
      return res.status(200).json({ success: true, message: "Transaction finalized." });
    }

    return res.status(400).json({ success: false, error: "Invalid action phase." });

  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
}