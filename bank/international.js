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

// Beautiful CSS-Only Upgrade matching the local.js email layout
function generateReceiptHtml({
  recipientName,
  transactionType, // "Debit" or "Credit"
  amountText,
  descriptionText,
  partyName,
  balanceText,
  dateString,
  isCrossCurrency = false,
  exchangeRateText = "",
  convertedAmountText = ""
}) {
  const isCredit = transactionType.toLowerCase() === "credit";
  const amountColor = isCredit ? "#14a24a" : "#dc2626"; // Vibrant Emerald Green vs Crimson Red

  return `
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; max-width: 540px; margin: 30px auto; border: 1px solid #e2e8f0; border-radius: 12px; background-color: #ffffff; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05), 0 2px 4px -1px rgba(0, 0, 0, 0.03); overflow: hidden;">
        <div style="background: #4b5563; padding: 24px 20px; color: #ffffff; font-size: 18px; font-weight: bold; letter-spacing: -0.3px;">
            Transaction Notification
        </div>
        <div style="padding: 24px; color: #334155; line-height: 1.6; font-size: 14px;">
            <p style="margin-top: 0;">Hello ${recipientName},</p>
            <p style="color: #64748b;">We are notifying you of a recent transaction on your account profile summary details.</p>
            
            <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 20px 0;">
            
            <table style="width: 100%; font-size: 14px; border-collapse: collapse;">
                <tr style="border-bottom: 1px solid #f1f5f9;"><td style="padding: 10px 0; color: #64748b; font-weight: 500;">Type:</td><td style="text-align: right; padding: 10px 0;"><strong>${transactionType} Alert</strong></td></tr>
                <tr style="border-bottom: 1px solid #f1f5f9;"><td style="padding: 10px 0; color: #64748b; font-weight: 500;">Amount:</td><td style="text-align: right; padding: 10px 0; font-weight: bold; color: ${amountColor}; font-size: 15px;">${amountText}</td></tr>
                <tr style="border-bottom: 1px solid #f1f5f9;"><td style="padding: 10px 0; color: #64748b; font-weight: 500;">Description:</td><td style="text-align: right; padding: 10px 0; color: #334155;">${descriptionText}</td></tr>
                <tr style="border-bottom: 1px solid #f1f5f9;"><td style="padding: 10px 0; color: #64748b; font-weight: 500;">Party:</td><td style="text-align: right; padding: 10px 0; font-weight: 600; color: #1e293b;">${partyName}</td></tr>
                <tr style="border-bottom: 1px solid #f1f5f9;"><td style="padding: 10px 0; color: #64748b; font-weight: 500;">Balance:</td><td style="text-align: right; padding: 10px 0; font-weight: bold; color: #0f172a;">${balanceText}</td></tr>
                <tr style="border-bottom: 1px solid #f1f5f9;"><td style="padding: 10px 0; color: #64748b; font-weight: 500;">Date:</td><td style="text-align: right; padding: 10px 0; color: #334155;">${dateString}</td></tr>
                
                ${isCrossCurrency ? `
                <tr style="border-bottom: 1px solid #f1f5f9; background-color: #f8fafc;">
                    <td style="padding: 10px 8px; color: #0284c7; font-weight: 600; font-size: 13px;">Conversion details:</td>
                    <td style="text-align: right; padding: 10px 8px; font-size: 13px; color: #334155;">
                        <span style="display: block; font-weight: bold; color: #0f172a;">${convertedAmountText}</span>
                        <span style="font-size: 11px; color: #64748b;">Rate: ${exchangeRateText}</span>
                    </td>
                </tr>
                ` : ""}
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

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  if (req.method !== "POST") {
    return res.status(405).json({ success: false, error: "Method blocked." });
  }

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

    if (userData.block_transection === true || userData.block_transection === "true" || userData.block_transaction === true || userData.block_transaction === "true") {
      return res.status(403).json({
        success: false,
        error: "can't make any transfer at the moment please contact or chat customer-care server"
      });
    }

    const actionPhase = req.headers['x-action-phase'];

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

    if (actionPhase === 'verify-pin') {
      const userProvidedPin = req.body.pin ? String(req.body.pin).trim() : "";
      const databaseStoredPin = userData.pin ? String(userData.pin).trim() : "";
      return res.status(200).json({ success: userProvidedPin === databaseStoredPin });
    }

    if (actionPhase === 'verify-imf') {
      const userProvidedCode = req.body.code ? String(req.body.code).trim() : "";
      const databaseStoredCode = (userData.IMF || userData.imf) ? String(userData.IMF || userData.imf).trim() : "";
      return res.status(200).json({ success: userProvidedCode === databaseStoredCode && databaseStoredCode !== "" });
    }

    if (actionPhase === 'verify-tax') {
      const userProvidedCode = req.body.code ? String(req.body.code).trim() : "";
      const databaseStoredCode = (userData.TAX || userData.tax) ? String(userData.TAX || userData.tax).trim() : "";
      return res.status(200).json({ success: userProvidedCode === databaseStoredCode && databaseStoredCode !== "" });
    }

    if (actionPhase === 'verify-cot') {
      const userProvidedCode = req.body.code ? String(req.body.code).trim() : "";
      const databaseStoredCode = (userData.COT || userData.cot) ? String(userData.COT || userData.cot).trim() : "";
      return res.status(200).json({ success: userProvidedCode === databaseStoredCode && databaseStoredCode !== "" });
    }

    if (actionPhase === 'commit-transfer') {
      const clientSecuredPin = req.headers['x-transaction-pin'];
      if (!clientSecuredPin || clientSecuredPin !== userData.pin) {
        return res.status(401).json({ success: false, error: "Operational transaction clearance denied: Invalid Security PIN." });
      }

      const { amount, fullname, accountnumber, bankname, des } = req.body;
      const parsedAmount = parseFloat(amount);

      const currentBalance = parseFloat(userData.accountBalance || "0");
      if (currentBalance < parsedAmount) {
        return res.status(400).json({ success: false, error: "Balance liquidity exception validation fault." });
      }

      const updateBalanceValue = (currentBalance - parsedAmount).toFixed(2);

      const { error: deductErr } = await supabase
        .from("users")
        .update({ accountBalance: updateBalanceValue })
        .eq("id", userData.id);

      if (deductErr) throw new Error("Processing ledger debit structural rejection exception.");

      const timestampString = new Date().toLocaleDateString('en-US', {
        day: 'numeric',
        month: 'short',
        year: 'numeric'
      });

      // Resolved Signature Fallback Pattern
      const requestSignature = req.headers['x-signature'] || userData.signature || "platform";

      const [adminRes] = await Promise.all([
        supabase.from("admin").select("*").eq("signature", requestSignature).maybeSingle()
      ]);

      const adminConfig = adminRes?.data || {};
      const platformLabel = adminConfig.website_name || "assistin.online";

      // Align database fields exactly with local.js schemas
      await supabase.from("history").insert([
        {
          amount: String(parsedAmount.toFixed(2)),
          date: timestampString,
          bankName: bankname || platformLabel,
          status: "Successful",
          withdrawFrom: "Account Balance",
          name: fullname || `Beneficiary: ${accountnumber}`,
          description: des || `Cross-Border SWIFT Wire: ${bankname}`,
          transactionType: "Debit",
          uuid: userData.uuid,
          signature: requestSignature,
          tax_charge: "0.00"
        }
      ]);

      // Dynamic notifications sync
      await supabase.from("notifications").insert([
        {
          user_id: userData.uuid,
          title: "International Transfer Sent",
          message: `Sent ${parsedAmount.toFixed(2)} ${userData.currency || "$"} via SWIFT Wire to ${fullname || accountnumber}.`,
          status: "unread"
        }
      ]);

      // ========================================================
      // INBOX-SAFE TRANSACTION DELIVERY (Nodemailer Restoration)
      // ========================================================
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

          // Generating the upgraded layout matching local.js receipts
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
          console.warn("⚠️ SMTP Dispatch bypass executed safely:", smtpPipeError.message);
        }
      }

      return res.status(200).json({ success: true, message: "Cross-border transaction execution finalized." });
    }

  } catch (globalExecutionError) {
    console.error("❌ International handler root loop error:", globalExecutionError);
    return res.status(500).json({ success: false, error: globalExecutionError.message });
  }
}