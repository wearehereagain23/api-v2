import { createClient } from "@supabase/supabase-js";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import ws from "ws";
import { getIsoCode } from "./currency.js";

const SUPABASE_URL = process.env.PUBLIC_SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const JWT_SECRET = process.env.JWT_SECRET;

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false },
  realtime: { transport: ws }
});

// Stripped-down, minimal transaction table template (Matches proven inbox-friendly template)
function generateReceiptHtml({
  recipientName,
  transactionType, // "Debit" or "Credit"
  amountText,
  descriptionText,
  partyName,
  balanceText,
  dateString
}) {
  const isCredit = transactionType.toLowerCase() === "credit";
  const amountColor = isCredit ? "#14a24a" : "#d97706"; // Green for credit, Amber/Red-orange for debit

  return `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; border: 1px solid #eeeeee; border-radius: 4px;">
        <div style="background: #4b5563; padding: 15px; color: #ffffff; font-size: 18px; font-weight: bold;">
            Transaction Notification
        </div>
        <div style="padding: 20px; color: #333333; line-height: 1.5;">
            <p>Hello ${recipientName},</p>
            <p>We are notifying you of a recent transaction on your account profile summary details.</p>
            <hr style="border: none; border-top: 1px solid #eeeeee; margin: 15px 0;">
            <table style="width: 100%; font-size: 14px;">
                <tr><td style="padding: 5px 0; color: #666666;">Type:</td><td><strong>${transactionType} Alert</strong></td></tr>
                <tr><td style="padding: 5px 0; color: #666666;">Amount:</td><td style="font-weight: bold; color: ${amountColor};">${amountText}</td></tr>
                <tr><td style="padding: 5px 0; color: #666666;">Description:</td><td>${descriptionText}</td></tr>
                <tr><td style="padding: 5px 0; color: #666666;">Party:</td><td>${partyName}</td></tr>
                <tr><td style="padding: 5px 0; color: #666666;">Balance:</td><td>${balanceText}</td></tr>
                <tr><td style="padding: 5px 0; color: #666666;">Date:</td><td>${dateString}</td></tr>
            </table>
            <hr style="border: none; border-top: 1px solid #eeeeee; margin: 15px 0;">
            <p style="font-size: 12px; color: #999999;">If you did not authorize this, please contact support services instantly.</p>
        </div>
    </div>
  `;
}

export default async function handler(req, res) {
  const requestOrigin = req.headers.origin;
  if (requestOrigin) {
    res.setHeader("Access-Control-Allow-Origin", requestOrigin);
  }
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "POST") return res.status(405).json({ success: false, error: "Method blocked." });

  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ success: false, error: "Access Denied: Auth context missing." });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decodedClaims = jwt.verify(token, JWT_SECRET);
    const senderUuid = decodedClaims.uuid || decodedClaims.id || (decodedClaims.user && decodedClaims.user.id);

    if (!senderUuid) {
      return res.status(401).json({ success: false, error: "Unauthorized Identity verification." });
    }

    const { accountNumber, amount, balanceSource, signature, isPreview, action } = req.body;

    if (action === "send_debit_email") {
      return res.status(200).json({ success: true, message: "Emails already handled inside transaction lifecycle." });
    }

    const baseAmount = parseFloat(amount) || 0;

    if (!accountNumber || baseAmount <= 0 || !balanceSource || !signature) {
      return res.status(400).json({ success: false, error: "Bad Request: Incomplete transfer properties." });
    }

    const [senderRes, recipientRes, adminRes] = await Promise.all([
      supabase.from("users").select("*").eq("uuid", senderUuid).single(),
      supabase.from("users").select("*").eq("accountNumber", String(accountNumber).trim()).maybeSingle(),
      supabase.from("admin").select("*").eq("signature", signature).maybeSingle()
    ]);

    if (senderRes.error || !senderRes.data) return res.status(404).json({ success: false, error: "Sender profile missing." });
    const senderData = senderRes.data;

    if (senderData.block_transaction === true || senderData.block_transaction === "true") {
      return res.status(403).json({ success: false, error: "User is blocked from making transfer please contact customer care." });
    }

    if (senderData.restricted === true || senderData.activeuser === false) {
      return res.status(403).json({ success: false, error: "Account structure currently placed under restriction holds." });
    }

    if (!recipientRes.data) return res.status(404).json({ success: false, error: "Destination account parameters not recognized." });
    const recipientData = recipientRes.data;

    if (senderData.uuid === recipientData.uuid) {
      return res.status(400).json({ success: false, error: "Self-transfer parameters rejected within local routes." });
    }

    if (balanceSource === "loanAmount") {
      if (!senderData.loanApprovalStatus || String(senderData.loanApprovalStatus).trim() !== "Approved") {
        return res.status(403).json({
          success: false,
          error: "Withdrawal Denied: Access to the loan allocation matrix is locked until your application status is 'Approved'."
        });
      }
    }

    const adminConfig = adminRes.data || {};
    const platformLabel = adminConfig.website_name || "assistin.online";

    const senderSymbol = String(senderData.currency || "$").trim();
    const recipientSymbol = String(recipientData.currency || "$").trim();
    const currenciesMatch = (senderSymbol === recipientSymbol);

    const taxPercentage = currenciesMatch ? 0 : parseFloat(senderData.tax_fee !== undefined ? senderData.tax_fee : 3);
    const independentTaxValue = parseFloat((baseAmount * (taxPercentage / 100)).toFixed(2));
    const totalSenderDeduction = parseFloat((baseAmount + independentTaxValue).toFixed(2));

    const senderAvailableBalance = parseFloat(senderData[balanceSource]) || 0;
    if (totalSenderDeduction > senderAvailableBalance) {
      return res.status(400).json({ success: false, error: "Insufficient liquidity core to cover transaction value and tax fees." });
    }

    let computationalExchangeRate = 1.0;
    let recipientCreditAmount = baseAmount;

    if (!currenciesMatch) {
      const senderCode = getIsoCode(senderSymbol);
      const recipientCode = getIsoCode(recipientSymbol);

      try {
        const responseFeed = await fetch(`https://open.er-api.com/v6/latest/${senderCode}`);
        if (!responseFeed.ok) throw new Error("API Node connection error.");

        const rateMapData = await responseFeed.json();
        const targetedCurrencyRate = rateMapData.rates[recipientCode];

        if (targetedCurrencyRate) {
          computationalExchangeRate = parseFloat(targetedCurrencyRate);
          recipientCreditAmount = parseFloat((baseAmount * computationalExchangeRate).toFixed(2));
        } else {
          throw new Error(`Target mapping symbol variant [${recipientCode}] not recognized on index.`);
        }
      } catch (err) {
        console.warn(`⚠️ Currency Engine Exception (${senderCode}->${recipientCode}):`, err.message);
        computationalExchangeRate = 1.0;
        recipientCreditAmount = baseAmount;
      }
    }

    if (isPreview === true || isPreview === "true") {
      return res.status(200).json({
        success: true,
        data: {
          recipientName: `${recipientData.firstname} ${recipientData.lastname}`,
          senderSymbol: senderSymbol,
          recipientSymbol: recipientSymbol,
          baseAmount: baseAmount.toFixed(2),
          taxApplied: independentTaxValue.toFixed(2),
          totalDeduction: totalSenderDeduction.toFixed(2),
          recipientCredit: recipientCreditAmount.toFixed(2),
          exchangeRate: computationalExchangeRate,
          currenciesMatch: currenciesMatch
        }
      });
    }

    const rawNewSenderBal = parseFloat((senderAvailableBalance - totalSenderDeduction).toFixed(2));
    const rawNewRecipientBal = parseFloat(((parseFloat(recipientData.accountBalance) || 0) + recipientCreditAmount).toFixed(2));

    const [senderUpdate, recipientUpdate] = await Promise.all([
      supabase.from("users").update({ [balanceSource]: rawNewSenderBal }).eq("uuid", senderData.uuid),
      supabase.from("users").update({ accountBalance: rawNewRecipientBal }).eq("uuid", recipientData.uuid)
    ]);

    if (senderUpdate.error) throw new Error(`Sender debit layer error: ${senderUpdate.error.message}`);
    if (recipientUpdate.error) throw new Error(`Recipient credit layer error: ${recipientUpdate.error.message}`);

    // Standardized short date string matching your previous project ("Jun 3, 2026")
    const formattedDateString = new Date().toLocaleDateString("en-US", {
      year: "numeric",
      month: "short",
      day: "numeric"
    });

    const senderFullName = `${senderData.firstname || ""} ${senderData.lastname || ""}`.trim();
    const receiverFullName = `${recipientData.firstname || ""} ${recipientData.lastname || ""}`.trim();

    let uiWithdrawLabel = "Account Balance";
    if (balanceSource === "accountTypeBalance") uiWithdrawLabel = senderData.accttype || "Fixed Vault Balance";
    if (balanceSource === "loanAmount") uiWithdrawLabel = "Loan Allocation";

    const historyEntries = [
      {
        date: formattedDateString,
        amount: String(baseAmount.toFixed(2)),
        bankName: platformLabel,
        status: "Successful",
        withdrawFrom: uiWithdrawLabel,
        name: receiverFullName,
        description: `Local transfer issued to ${receiverFullName}`,
        transactionType: "Debit",
        uuid: senderData.uuid,
        signature: signature,
        tax_charge: String(independentTaxValue.toFixed(2))
      },
      {
        date: formattedDateString,
        amount: String(recipientCreditAmount.toFixed(2)),
        bankName: platformLabel,
        status: "Successful",
        withdrawFrom: "account balance",
        name: senderFullName,
        description: `Local funds deposited by ${senderFullName}`,
        transactionType: "Credit",
        uuid: recipientData.uuid,
        signature: signature,
        tax_charge: null
      }
    ];

    const historyInsert = await supabase.from("history").insert(historyEntries);
    if (historyInsert.error) {
      console.error("⚠️ History Ledger Error Trace:", historyInsert.error.message);
    }

    await supabase.from("notifications").insert([
      { user_id: senderData.uuid, title: "Local Transfer Issued", message: `Sent ${baseAmount} ${senderSymbol} from ${uiWithdrawLabel}. Tax: ${independentTaxValue} ${senderSymbol}.`, status: "unread" },
      { user_id: recipientData.uuid, title: "Local Funds Deposited", message: `Received ${recipientCreditAmount} ${recipientSymbol} from ${senderFullName}.`, status: "unread" }
    ]);

    // ========================================================
    // SMTP BROADCAST
    // ========================================================
    if (adminConfig.smtp_host && adminConfig.smtp_email && adminConfig.smtp_password) {
      try {
        const mailTransporter = nodemailer.createTransport({
          host: adminConfig.smtp_host.trim(),
          port: parseInt(adminConfig.smtp_port, 10) || 465,
          secure: parseInt(adminConfig.smtp_port, 10) === 465,
          auth: {
            user: adminConfig.smtp_email.trim(),
            pass: adminConfig.smtp_password.trim()
          }
        });

        const senderAddressEmail = adminConfig.smtp_email.trim();

        // DEBIT RECEIPT (SENDER EMAIL)
        const debitHtml = generateReceiptHtml({
          recipientName: senderData.firstname || "User",
          transactionType: "Debit",
          amountText: `-${senderSymbol}${baseAmount.toFixed(2)}`,
          descriptionText: `Local transfer issued to ${receiverFullName}`,
          partyName: receiverFullName,
          balanceText: `${senderSymbol}${rawNewSenderBal.toFixed(2)}`,
          dateString: formattedDateString
        });

        // CREDIT RECEIPT (RECIPIENT EMAIL)
        const creditHtml = generateReceiptHtml({
          recipientName: recipientData.firstname || "User",
          transactionType: "Credit",
          amountText: `+${recipientSymbol}${recipientCreditAmount.toFixed(2)}`,
          descriptionText: `Local funds deposited by ${senderFullName}`,
          partyName: senderFullName,
          balanceText: `${recipientSymbol}${rawNewRecipientBal.toFixed(2)}`,
          dateString: formattedDateString
        });

        await Promise.all([
          mailTransporter.sendMail({
            from: `"Notification Center" <${senderAddressEmail}>`,
            to: senderData.email.trim(),
            replyTo: `"Notification Center" <${senderAddressEmail}>`,
            // Simple proven subject format
            subject: `Transaction Alert: Debit of ${senderSymbol}${baseAmount.toFixed(2)}`,
            html: debitHtml,
            headers: {
              "MIME-Version": "1.0",
              "X-Mailer": "Nodemailer"
            }
          }),
          mailTransporter.sendMail({
            from: `"Notification Center" <${senderAddressEmail}>`,
            to: recipientData.email.trim(),
            replyTo: `"Notification Center" <${senderAddressEmail}>`,
            // Simple proven subject format
            subject: `Transaction Alert: Credit of ${recipientSymbol}${recipientCreditAmount.toFixed(2)}`,
            html: creditHtml,
            headers: {
              "MIME-Version": "1.0",
              "X-Mailer": "Nodemailer"
            }
          })
        ]);
        console.log("📨 Symmetrical inbox-friendly receipts dispatched successfully.");

      } catch (nodemailerErr) {
        console.warn("⚠️ SMTP Dynamic dispatch failed. Trace details:", nodemailerErr.message);
      }
    }

    return res.status(200).json({ success: true, message: "Ledger clearance transaction executed successfully." });

  } catch (globalExecutionError) {
    console.error("❌ Local clearing execution error:", globalExecutionError);
    return res.status(500).json({ success: false, error: globalExecutionError.message });
  }
}