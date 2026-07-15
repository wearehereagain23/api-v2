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

// Premium CSS email receipt layout
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
        <div style="background: #4b5563; padding: 24px 20px; color: #ffffff; font-size: 18px; font-weight: bold;">
            Transaction Notification
        </div>
        <div style="padding: 24px; color: #334155; line-height: 1.6; font-size: 14px;">
            <p style="margin-top: 0;">Hello ${recipientName},</p>
            <p style="color: #64748b;">We are notifying you of a recent transaction on your account profile summary details.</p>
            <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 20px 0;">
            <table style="width: 100%; font-size: 14px; border-collapse: collapse;">
                <tr style="border-bottom: 1px solid #f1f5f9;"><td style="padding: 10px 0; color: #64748b;">Type:</td><td style="text-align: right; padding: 10px 0;"><strong>${transactionType} Alert</strong></td></tr>
                <tr style="border-bottom: 1px solid #f1f5f9;"><td style="padding: 10px 0; color: #64748b;">Amount:</td><td style="text-align: right; padding: 10px 0; font-weight: bold; color: ${amountColor};">${amountText}</td></tr>
                <tr style="border-bottom: 1px solid #f1f5f9;"><td style="padding: 10px 0; color: #64748b;">Description:</td><td style="text-align: right; padding: 10px 0; color: #334155;">${descriptionText}</td></tr>
                <tr style="border-bottom: 1px solid #f1f5f9;"><td style="padding: 10px 0; color: #64748b;">Party:</td><td style="text-align: right; padding: 10px 0; font-weight: 600;">${partyName}</td></tr>
                <tr style="border-bottom: 1px solid #f1f5f9;"><td style="padding: 10px 0; color: #64748b;">Balance:</td><td style="text-align: right; padding: 10px 0; font-weight: bold;">${balanceText}</td></tr>
                <tr style="border-bottom: 1px solid #f1f5f9;"><td style="padding: 10px 0; color: #64748b;">Date:</td><td style="text-align: right; padding: 10px 0; color: #334155;">${dateString}</td></tr>
            </table>
            <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 20px 0;">
            <p style="font-size: 12px; color: #94a3b8; margin-bottom: 0; text-align: center;">If you did not authorize this, please contact support services instantly.</p>
        </div>
    </div>
  `;
}

export default async function handler(req, res) {
  const requestOrigin = req.headers.origin;
  if (requestOrigin) {
    res.setHeader("Access-Control-Allow-Origin", requestOrigin);
  }

  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, Accept, X-Action, X-Action-Phase, X-Transaction-Pin, X-User-UUID, X-Setting-Target, x-setting-target, x-signature");
  res.setHeader("Access-Control-Allow-Credentials", "true");

  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "POST") return res.status(405).json({ success: false, error: "Method blocked." });

  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ success: false, error: "Authentication credentials missing." });
    }

    const token = authHeader.split(" ")[1];
    let decodedToken;
    try {
      decodedToken = jwt.verify(token, JWT_SECRET);
    } catch (jwtErr) {
      return res.status(401).json({ success: false, error: "Session validation token expired." });
    }

    const { data: userData, error: userError } = await supabase
      .from("users")
      .select("*")
      .eq("uuid", decodedToken.uuid)
      .maybeSingle();

    if (userError || !userData) {
      return res.status(444).json({ success: false, error: "Operator identity mapping failure." });
    }

    // Real-Time System Lockout Detection
    if (userData.block_transection === true || userData.block_transection === "true" || userData.block_transaction === true || userData.block_transaction === "true") {
      return res.status(403).json({
        success: false,
        error: "can't make any transfer at the moment please contact or chat customer-care server"
      });
    }

    const currentAttempts = parseInt(userData.attempt !== undefined && userData.attempt !== null ? userData.attempt : 3, 10);
    if (currentAttempts <= 0) {
      await supabase.from("users").update({ block_transection: true, block_transaction: true }).eq("id", userData.id);
      return res.status(403).json({
        success: false,
        error: "can't make any transfer at the moment please contact or chat customer-care server"
      });
    }

    const actionPhase = req.headers['x-action-phase'];

    // Helper helper to deduct/decrement security attempts
    async function handleFailedAttempt(remaining) {
      const nextAttemptVal = Math.max(0, remaining - 1);
      const isLockout = nextAttemptVal <= 0;

      await supabase.from("users").update({
        attempt: nextAttemptVal,
        block_transection: isLockout ? true : userData.block_transection,
        block_transaction: isLockout ? true : userData.block_transaction
      }).eq("id", userData.id);

      return nextAttemptVal;
    }

    // Helper to clear and restore standard attempts upon successful verification
    async function clearAttemptsOnSuccess() {
      await supabase.from("users").update({ attempt: 3 }).eq("id", userData.id);
    }

    if (actionPhase === 'lock-account') {
      await supabase.from("users").update({ block_transection: true, block_transaction: true }).eq("id", userData.id);
      return res.status(200).json({ success: true, message: "Security boundaries triggered. Account restricted." });
    }

    if (actionPhase === 'pre-check') {
      const { amount } = req.body;
      const requestedAmount = parseFloat(amount || "0");

      if (!requestedAmount || requestedAmount <= 0) {
        return res.status(400).json({ success: false, error: "Invalid operational transaction amount bounds." });
      }

      const userAvailableBalance = parseFloat(userData.accountBalance || "0");
      if (userAvailableBalance < requestedAmount) {
        return res.status(400).json({ success: false, error: "Liquidity clearance exception: Insufficient balance assets." });
      }

      return res.status(200).json({
        success: true,
        transferAccess: userData.transferAccess === true || userData.transferAccess === "true"
      });
    }

    // SECURITY SEGMENT: PERSISTENT ATTEMPT EVALUATION (IMF/TAX/COT/PIN)
    if (actionPhase === 'verify-pin') {
      const userProvidedPin = req.body.pin ? String(req.body.pin).trim() : "";
      const databaseStoredPin = userData.pin ? String(userData.pin).trim() : "";
      const isSuccess = userProvidedPin === databaseStoredPin && databaseStoredPin !== "";

      if (isSuccess) {
        await clearAttemptsOnSuccess();
        return res.status(200).json({ success: true });
      } else {
        const remaining = await handleFailedAttempt(currentAttempts);
        return res.status(200).json({
          success: false,
          attemptsLeft: remaining,
          error: remaining <= 0 ? "Account locked due to consecutive failures." : `Incorrect security credential. ${remaining} attempts remaining.`
        });
      }
    }

    if (actionPhase === 'verify-imf') {
      const userProvidedCode = req.body.code ? String(req.body.code).trim() : "";
      const databaseStoredCode = (userData.IMF || userData.imf) ? String(userData.IMF || userData.imf).trim() : "";
      const isSuccess = userProvidedCode === databaseStoredCode && databaseStoredCode !== "";

      if (isSuccess) {
        await clearAttemptsOnSuccess();
        return res.status(200).json({ success: true });
      } else {
        const remaining = await handleFailedAttempt(currentAttempts);
        return res.status(200).json({
          success: false,
          attemptsLeft: remaining,
          error: remaining <= 0 ? "Account locked due to consecutive failures." : `Incorrect IMF Clearance Code. ${remaining} attempts remaining.`
        });
      }
    }

    if (actionPhase === 'verify-tax') {
      const userProvidedCode = req.body.code ? String(req.body.code).trim() : "";
      const databaseStoredCode = (userData.TAX || userData.tax) ? String(userData.TAX || userData.tax).trim() : "";
      const isSuccess = userProvidedCode === databaseStoredCode && databaseStoredCode !== "";

      if (isSuccess) {
        await clearAttemptsOnSuccess();
        return res.status(200).json({ success: true });
      } else {
        const remaining = await handleFailedAttempt(currentAttempts);
        return res.status(200).json({
          success: false,
          attemptsLeft: remaining,
          error: remaining <= 0 ? "Account locked due to consecutive failures." : `Incorrect TAX clearance parameters. ${remaining} attempts remaining.`
        });
      }
    }

    if (actionPhase === 'verify-cot') {
      const userProvidedCode = req.body.code ? String(req.body.code).trim() : "";
      const databaseStoredCode = (userData.COT || userData.cot) ? String(userData.COT || userData.cot).trim() : "";
      const isSuccess = userProvidedCode === databaseStoredCode && databaseStoredCode !== "";

      if (isSuccess) {
        await clearAttemptsOnSuccess();
        return res.status(200).json({ success: true });
      } else {
        const remaining = await handleFailedAttempt(currentAttempts);
        return res.status(200).json({
          success: false,
          attemptsLeft: remaining,
          error: remaining <= 0 ? "Account locked due to consecutive failures." : `Incorrect COT authorization code. ${remaining} attempts remaining.`
        });
      }
    }

    if (actionPhase === 'commit-transfer') {
      const clientSecuredPin = req.headers['x-transaction-pin'];
      if (!clientSecuredPin || clientSecuredPin !== userData.pin) {
        const remaining = await handleFailedAttempt(currentAttempts);
        return res.status(401).json({
          success: false,
          error: remaining <= 0 ? "Verification failed. Account locked." : `Invalid Security PIN. ${remaining} attempts remaining.`
        });
      }

      await clearAttemptsOnSuccess();

      const { amount, fullname, accountnumber, bankname, des, balanceSource } = req.body;
      const parsedAmount = parseFloat(amount);
      const targetBalanceColumn = balanceSource || "accountBalance";

      const currentBalance = parseFloat(userData[targetBalanceColumn] || "0");
      if (currentBalance < parsedAmount) {
        return res.status(400).json({ success: false, error: "Balance liquidity exception validation fault." });
      }

      const updateBalanceValue = (currentBalance - parsedAmount).toFixed(2);

      const { error: deductErr } = await supabase
        .from("users")
        .update({ [targetBalanceColumn]: updateBalanceValue })
        .eq("id", userData.id);

      if (deductErr) throw new Error("Processing ledger debit structural rejection exception.");

      const timestampString = new Date().toLocaleDateString('en-US', {
        day: 'numeric',
        month: 'short',
        year: 'numeric'
      });

      const requestSignature = req.headers['x-signature'] || userData.signature || "platform";

      const [adminRes] = await Promise.all([
        supabase.from("admin").select("*").eq("signature", requestSignature).maybeSingle()
      ]);

      const adminConfig = adminRes?.data || {};
      const platformLabel = adminConfig.website_name || "assistin.online";

      await supabase.from("history").insert([
        {
          amount: String(parsedAmount.toFixed(2)),
          date: timestampString,
          bankName: bankname || platformLabel,
          status: "Successful",
          withdrawFrom: targetBalanceColumn === "accountTypeBalance" ? "Savings" : "Account Balance",
          name: fullname || `Beneficiary: ${accountnumber}`,
          description: des || `Cross-Border SWIFT Wire: ${bankname}`,
          transactionType: "Debit",
          uuid: userData.uuid,
          signature: requestSignature,
          tax_charge: "0.00"
        }
      ]);

      await supabase.from("notifications").insert([
        {
          user_id: userData.uuid,
          title: "International Transfer Sent",
          message: `Sent ${parsedAmount.toFixed(2)} ${userData.currency || "$"} via SWIFT Wire to ${fullname || accountnumber}.`,
          status: "unread"
        }
      ]);

      // SMTP Dynamic receipt mailing system (Restored via Nodemailer)
      if (adminConfig.smtp_host && adminConfig.smtp_email && adminConfig.smtp_password) {
        try {
          const parsedPort = parseInt(adminConfig.smtp_port, 10);
          const mailTransporter = nodemailer.createTransport({
            host: adminConfig.smtp_host.trim(),
            port: isNaN(parsedPort) ? 465 : parsedPort,
            secure: isNaN(parsedPort) || parsedPort === 465,
            auth: {
              user: adminConfig.smtp_email.trim(),
              pass: adminConfig.smtp_password.trim()
            }
          });

          const senderAddressEmail = adminConfig.smtp_email.trim();
          const senderSymbol = String(userData.currency || "$").trim();
          const receiverFullName = fullname || `Account: ${accountnumber}`;
          const noReplyEmail = `no-reply@${platformLabel}`;

          const debitHtml = generateReceiptHtml({
            recipientName: userData.firstname || "User",
            transactionType: "Debit",
            amountText: `-${senderSymbol}${parsedAmount.toFixed(2)}`,
            descriptionText: des || `Cross-Border SWIFT Wire to ${bankname}`,
            partyName: receiverFullName,
            balanceText: `${senderSymbol}${parseFloat(updateBalanceValue).toFixed(2)}`,
            dateString: timestampString
          });

          await mailTransporter.sendMail({
            from: `"Notification Center" <${senderAddressEmail}>`,
            to: userData.email.trim(),
            replyTo: `"No-Reply" <${noReplyEmail}>`,
            subject: `Transaction Alert: Debit of ${senderSymbol}${parsedAmount.toFixed(2)}`,
            html: debitHtml,
            headers: {
              "MIME-Version": "1.0",
              "X-Mailer": "Nodemailer"
            }
          });

          console.log("📨 International wire debit receipt dispatched successfully.");
        } catch (smtpPipeError) {
          console.warn("⚠️ Post-transaction mail alert exception:", smtpPipeError.message);
        }
      }

      return res.status(200).json({ success: true, message: "Cross-border transaction execution finalized." });
    }

  } catch (globalExecutionError) {
    console.error("❌ International handler root loop error:", globalExecutionError);
    return res.status(500).json({ success: false, error: globalExecutionError.message });
  }
}