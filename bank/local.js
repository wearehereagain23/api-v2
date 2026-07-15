import { createClient } from "@supabase/supabase-js";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer"; // Back to Nodemailer!
import ws from "ws";
import { getIsoCode } from "./currency.js";

const SUPABASE_URL = process.env.PUBLIC_SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const JWT_SECRET = process.env.JWT_SECRET;

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false },
  realtime: { transport: ws }
});

// Premium, Modern HTML Receipt Template Generator
function generateReceiptHtml({
  brandName,
  recipientName,
  senderName,
  transactionType, // "Debit" or "Credit"
  amountText,
  taxText,
  totalText,
  dateString,
  referenceId,
  accountSourceLabel,
  status = "Successful",
  // Currency Conversion Parameters
  isCrossCurrency = false,
  exchangeRateText = "",
  convertedAmountText = ""
}) {
  const isDebit = transactionType.toLowerCase() === "debit";

  // Clean, modern semantic color palettes
  const badgeBg = isDebit ? "#fff7ed" : "#f0fdf4";
  const badgeText = isDebit ? "#c2410c" : "#15803d";
  const amountColor = isDebit ? "#0f172a" : "#16a34a";
  const partyLabel = isDebit ? "Recipient" : "Sender";
  const partyValue = isDebit ? recipientName : senderName;

  return `
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #f8fafc; padding: 40px 16px; margin: 0;">
      <div style="max-width: 540px; margin: 0 auto; background-color: #ffffff; border-radius: 16px; border: 1px solid #e2e8f0; overflow: hidden; box-shadow: 0 10px 15px -3px rgba(0,0,0,0.03), 0 4px 6px -4px rgba(0,0,0,0.03);">
        
        <!-- Modern Subtle Gradient Header Accent -->
        <div style="background: linear-gradient(135deg, #475569 0%, #1e293b 100%); padding: 32px 24px; text-align: center; color: #ffffff;">
          <h2 style="margin: 0; font-size: 22px; font-weight: 700; letter-spacing: -0.5px; color: #ffffff;">${brandName}</h2>
          <p style="margin: 6px 0 0 0; font-size: 13px; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.8px; font-weight: 600;">System Notification</p>
        </div>

        <div style="padding: 36px 32px;">
          
          <!-- Large Clean Hero Amount Block -->
          <div style="text-align: center; margin-bottom: 32px;">
            <p style="margin: 0; font-size: 13px; color: #64748b; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;">
              ${isDebit ? 'Total Allocation Out' : 'Net Funds Deposited'}
            </p>
            <h1 style="margin: 8px 0; font-size: 36px; font-weight: 800; color: ${amountColor}; letter-spacing: -1px;">
              ${isDebit ? '-' : '+'}${amountText}
            </h1>
            <div style="display: inline-block; background-color: ${badgeBg}; color: ${badgeText}; font-size: 11px; font-weight: 700; padding: 5px 14px; border-radius: 9999px; text-transform: uppercase; letter-spacing: 0.5px;">
              ${transactionType} &bull; ${status}
            </div>
          </div>

          <!-- Transaction Data Grid -->
          <div style="border-top: 1px solid #f1f5f9; padding-top: 24px; margin-bottom: 24px;">
            <table style="width: 100%; border-collapse: collapse; font-size: 14px;">
              <tr style="height: 38px;">
                <td style="color: #64748b; font-weight: 500;">Reference ID</td>
                <td style="text-align: right; color: #0f172a; font-weight: 600; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 13px;">${referenceId}</td>
              </tr>
              <tr style="height: 38px;">
                <td style="color: #64748b; font-weight: 500;">Date</td>
                <td style="text-align: right; color: #0f172a; font-weight: 500;">${dateString}</td>
              </tr>
              <tr style="height: 38px;">
                <td style="color: #64748b; font-weight: 500;">${partyLabel}</td>
                <td style="text-align: right; color: #0f172a; font-weight: 600;">${partyValue}</td>
              </tr>
              <tr style="height: 38px;">
                <td style="color: #64748b; font-weight: 500;">Method / Account</td>
                <td style="text-align: right; color: #0f172a; font-weight: 500;">${accountSourceLabel}</td>
              </tr>

              <!-- Dynamic Multi-Currency UI Block (Only displays when cross-currency conversions occur) -->
              ${isCrossCurrency ? `
              <tr style="height: 12px;"><td colspan="2"></td></tr>
              <tr style="border-top: 1px dashed #e2e8f0; height: 12px;"><td colspan="2"></td></tr>
              <tr style="height: 34px;">
                <td style="color: #64748b; font-weight: 500;">Exchange Rate Applied</td>
                <td style="text-align: right; color: #0284c7; font-weight: 600; font-size: 13px;">${exchangeRateText}</td>
              </tr>
              <tr style="height: 34px;">
                <td style="color: #64748b; font-weight: 500;">Converted Base Value</td>
                <td style="text-align: right; color: #0f172a; font-weight: 600;">${convertedAmountText}</td>
              </tr>
              ` : ""}
            </table>
          </div>

          <!-- Dynamic Financial Impact Summary Card -->
          <div style="background-color: #f8fafc; border-radius: 12px; padding: 20px; border: 1px solid #f1f5f9;">
            <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
              <tr style="height: 28px;">
                <td style="color: #64748b;">Principal Transfer Sum</td>
                <td style="text-align: right; color: #334155; font-weight: 600;">${amountText}</td>
              </tr>
              <tr style="height: 28px;">
                <td style="color: #64748b;">Security Processing Fee</td>
                <td style="text-align: right; color: #334155; font-weight: 600;">${taxText}</td>
              </tr>
              <tr style="height: 38px; border-top: 1px solid #e2e8f0;">
                <td style="color: #0f172a; font-weight: 700; font-size: 14px; padding-top: 8px;">Total Account Impact</td>
                <td style="text-align: right; color: #0f172a; font-weight: 800; font-size: 16px; padding-top: 8px;">${totalText}</td>
              </tr>
            </table>
          </div>

          <!-- Ultra-clean security footer -->
          <div style="text-align: center; margin-top: 32px;">
            <p style="margin: 0; font-size: 11px; color: #94a3b8; line-height: 1.5;">
              Authorized transaction update. If unauthorized, please secure your profile summary settings.
            </p>
          </div>

        </div>

        <!-- Clean Footer -->
        <div style="background-color: #f8fafc; padding: 24px; text-align: center; border-top: 1px solid #e2e8f0; font-size: 11px; color: #94a3b8;">
          <p style="margin: 0 0 2px 0;">This is an automatic notification pipeline. Replies to this address are not monitored.</p>
          <p style="margin: 0;">&copy; ${new Date().getFullYear()} ${brandName}. All rights reserved.</p>
        </div>
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
    // SMTP BROADCAST (Nodemailer Engine)
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
        const cleanSignatureTag = platformLabel;

        const debitRefId = `TXN-${Math.floor(100000 + Math.random() * 900000)}-D`;
        const creditRefId = `TXN-${Math.floor(100000 + Math.random() * 900000)}-C`;

        // Generate Debit Email Content
        const debitHtml = generateReceiptHtml({
          brandName: cleanSignatureTag,
          recipientName: receiverFullName,
          senderName: senderFullName,
          transactionType: "Debit",
          amountText: `${senderSymbol}${baseAmount.toFixed(2)}`,
          taxText: `${senderSymbol}${independentTaxValue.toFixed(2)}`,
          totalText: `${senderSymbol}${totalSenderDeduction.toFixed(2)}`,
          dateString: formattedDateString,
          referenceId: debitRefId,
          accountSourceLabel: uiWithdrawLabel,
          // Conversion conditional styling
          isCrossCurrency: !currenciesMatch,
          exchangeRateText: currenciesMatch ? "" : `1 ${senderSymbol} = ${computationalExchangeRate.toFixed(4)} ${recipientSymbol}`,
          convertedAmountText: currenciesMatch ? "" : `${recipientSymbol}${recipientCreditAmount.toFixed(2)}`
        });

        // Generate Credit Email Content
        const creditHtml = generateReceiptHtml({
          brandName: cleanSignatureTag,
          recipientName: receiverFullName,
          senderName: senderFullName,
          transactionType: "Credit",
          amountText: `${recipientSymbol}${recipientCreditAmount.toFixed(2)}`,
          taxText: `${recipientSymbol}0.00`,
          totalText: `${recipientSymbol}${recipientCreditAmount.toFixed(2)}`,
          dateString: formattedDateString,
          referenceId: creditRefId,
          accountSourceLabel: "Account Balance",
          // Conversion conditional styling
          isCrossCurrency: !currenciesMatch,
          exchangeRateText: currenciesMatch ? "" : `1 ${senderSymbol} = ${computationalExchangeRate.toFixed(4)} ${recipientSymbol}`,
          convertedAmountText: currenciesMatch ? "" : `${senderSymbol}${baseAmount.toFixed(2)}`
        });

        await Promise.all([
          mailTransporter.sendMail({
            from: `"Notification Center" <${senderAddressEmail}>`,
            to: senderData.email.trim(),
            replyTo: `"Notification Center" <${senderAddressEmail}>`,
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
            subject: `Transaction Alert: Credit of ${recipientSymbol}${recipientCreditAmount.toFixed(2)}`,
            html: creditHtml,
            headers: {
              "MIME-Version": "1.0",
              "X-Mailer": "Nodemailer"
            }
          })
        ]);
        console.log("📨 Premium transactional emails sent successfully via Nodemailer!");

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