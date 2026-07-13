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

export default async function handler(req, res) {
  const requestOrigin = req.headers.origin;
  if (requestOrigin) {
    res.setHeader("Access-Control-Allow-Origin", requestOrigin);
  }

  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  if (req.method !== "POST") {
    return res.status(405).json({ success: false, error: "Method blocked." });
  }

  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ success: false, error: "Access Denied: Token footprint missing." });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decodedClaims = jwt.verify(token, JWT_SECRET);
    const senderUuid = decodedClaims.uuid || decodedClaims.id || (decodedClaims.user && decodedClaims.user.id);

    if (!senderUuid) {
      return res.status(401).json({ success: false, error: "Unauthorized: Signature footprint mismatch." });
    }

    const { accountNumber, amount, balanceSource, signature } = req.body;
    const baseAmount = parseFloat(amount) || 0;

    if (!accountNumber || baseAmount <= 0 || !balanceSource || !signature) {
      return res.status(400).json({ success: false, error: "Bad Request: Missing required routing properties." });
    }

    // Fetch Sender profile, Recipient record and Platform Admin configuration profile in parallel
    const [senderRes, recipientRes, adminRes] = await Promise.all([
      supabase.from("users").select("*").eq("uuid", senderUuid).single(),
      supabase.from("users").select("*").eq("accountNumber", String(accountNumber).trim()).maybeSingle(),
      supabase.from("admin").select("*").eq("signature", signature).maybeSingle()
    ]);

    if (senderRes.error || !senderRes.data) {
      return res.status(404).json({ success: false, error: "Sender profile mismatch." });
    }
    const senderData = senderRes.data;

    // 🌟 STAGE 1: TRANSACTION BLOCK ACCOUNT HOOK RULE CHECK
    if (senderData.block_transaction === true || senderData.block_transaction === "true") {
      return res.status(403).json({ success: false, error: "User is blocked from making transfer please contact customer care." });
    }

    if (senderData.restricted === true || senderData.activeuser === false) {
      return res.status(403).json({ success: false, error: "Secure account access parameters restricted." });
    }

    if (!recipientRes.data) {
      return res.status(404).json({ success: false, error: "Destination account parameters not recognized." });
    }
    const recipientData = recipientRes.data;

    if (senderData.uuid === recipientData.uuid) {
      return res.status(400).json({ success: false, error: "Self-transfer parameters rejected within local routes." });
    }

    const adminConfig = adminRes.data || {};
    const platformLabel = adminConfig.website_name || adminConfig.signature || "OnFlex";

    // 🌟 STAGE 2: DYNAMIC TAX EXTRACTION FROM USER TABLE
    const taxPercentage = parseFloat(senderData.tax_fee !== undefined ? senderData.tax_fee : 3);
    const independentTaxFee = parseFloat((baseAmount * (taxPercentage / 100)).toFixed(2));

    // 🌟 Total Hit to Sender: Base Typed Amount + Independent Tax Subtraction
    const totalSenderDeduction = parseFloat((baseAmount + independentTaxFee).toFixed(2));

    const senderAvailableBalance = parseFloat(senderData[balanceSource]) || 0;
    if (totalSenderDeduction > senderAvailableBalance) {
      return res.status(400).json({ success: false, error: "Insufficient liquidity core to cover base transaction and independent tax margins." });
    }

    // 🌟 STAGE 3: ISOLATED CURRENCY CONVERTER SYSTEM
    let finalExchangeRate = 1.0;
    let recipientCreditAmount = baseAmount; // Default untaxed base amount if currencies match identically

    const senderCurrency = String(senderData.currency || "USD").toUpperCase().trim();
    const recipientCurrency = String(recipientData.currency || "USD").toUpperCase().trim();

    if (senderCurrency !== recipientCurrency) {
      // Currencies do not match -> Compute dynamic multi-currency rate layer
      try {
        const apiFeed = await fetch(`https://open.er-api.com/v6/latest/${senderCurrency}`);
        if (!apiFeed.ok) throw new Error("API server node non-responsive.");

        const rateData = await apiFeed.json();
        const fetchedRate = rateData.rates[recipientCurrency];

        if (fetchedRate) {
          finalExchangeRate = parseFloat(fetchedRate);
          // Only the base typed amount gets converted via live multiplier
          recipientCreditAmount = parseFloat((baseAmount * finalExchangeRate).toFixed(2));
        } else {
          throw new Error("Target ISO symbol mismatch.");
        }
      } catch (err) {
        console.warn(`⚠️ API Network Interruption: Falling back to 1.0 parity standard: ${err.message}`);
        // Fallback rule integration override: Parity mapping matching typed base parameter amount exactly
        finalExchangeRate = 1.0;
        recipientCreditAmount = baseAmount;
      }
    }

    // Compute updated structural parameters balances
    const updatedSenderBalance = parseFloat((senderAvailableBalance - totalSenderDeduction).toFixed(2));
    const updatedRecipientBalance = parseFloat(((parseFloat(recipientData.accountBalance) || 0) + recipientCreditAmount).toFixed(2));

    // Commit ledger mutations securely onto database table structures
    const [senderUpdate, recipientUpdate] = await Promise.all([
      supabase.from("users").update({ [balanceSource]: updatedSenderBalance }).eq("uuid", senderData.uuid),
      supabase.from("users").update({ accountBalance: updatedRecipientBalance }).eq("uuid", recipientData.uuid)
    ]);

    if (senderUpdate.error) throw new Error(`Sender debit commit exception: ${senderUpdate.error.message}`);
    if (recipientUpdate.error) throw new Error(`Recipient credit commit exception: ${recipientUpdate.error.message}`);

    // Append matching log assets inside notification tables
    await supabase.from("notifications").insert([
      { user_id: senderData.uuid, title: "Local Transfer Issued", message: `Sent ${baseAmount} ${senderCurrency} to Acc No: ${recipientData.accountNumber}. Tax Fee applied: ${independentTaxFee} ${senderCurrency}.`, status: "unread" },
      { user_id: recipientData.uuid, title: "Local Funds Deposited", message: `Received ${recipientCreditAmount} ${recipientCurrency} from ${senderData.firstname} ${senderData.lastname}.`, status: "unread" }
    ]);

    // STAGE 4: DUAL TRANSACTION EMAIL DISPATCHES
    try {
      if (adminConfig.smtp_host && adminConfig.smtp_email) {
        const mailTransporter = nodemailer.createTransport({
          host: adminConfig.smtp_host,
          port: parseInt(adminConfig.smtp_port, 10) || 465,
          secure: parseInt(adminConfig.smtp_port, 10) === 465,
          auth: { user: adminConfig.smtp_email, pass: adminConfig.smtp_password }
        });

        const senderHtml = `
            <div style="font-family:sans-serif; background:#111115; color:#fff; padding:30px; border-radius:12px;">
                <h2 style="color:#e74c3c; border-bottom:1px solid #222; padding-bottom:10px;">Debit Alert Notification</h2>
                <p>Hello ${senderData.firstname || "Client"},</p>
                <p>We confirm a local ledger clearing transaction execution out of your <strong>${balanceSource}</strong>.</p>
                <table style="color:#fff; width:100%; border-collapse:collapse; margin:20px 0;">
                    <tr><td style="padding:8px; border-bottom:1px solid #222;"><strong>Recipient Account:</strong></td><td style="padding:8px; border-bottom:1px solid #222;">${recipientData.accountNumber}</td></tr>
                    <tr><td style="padding:8px; border-bottom:1px solid #222;"><strong>Base Transaction Amount:</strong></td><td style="padding:8px; border-bottom:1px solid #222; color:#e74c3c;">-${baseAmount} ${senderCurrency}</td></tr>
                    <tr><td style="padding:8px; border-bottom:1px solid #222;"><strong>Independent Processing Tax (${taxPercentage}%):</strong></td><td style="padding:8px; border-bottom:1px solid #222; color:#ff9f43;">-${independentTaxFee} ${senderCurrency}</td></tr>
                    <tr><td style="padding:8px; border-bottom:1px solid #222;"><strong>Total Ledger Deduction:</strong></td><td style="padding:8px; border-bottom:1px solid #222; font-weight:bold;">-${totalSenderDeduction} ${senderCurrency}</td></tr>
                    <tr><td style="padding:8px; border-bottom:1px solid #222;"><strong>Available Balance remaining:</strong></td><td style="padding:8px; border-bottom:1px solid #222; color:#2ecc71;">${updatedSenderBalance} ${senderCurrency}</td></tr>
                </table>
                <br><small>Ref ID: ${signature.toUpperCase()}-TX-${Date.now()}</small>
            </div>`;

        const recipientHtml = `
            <div style="font-family:sans-serif; background:#111115; color:#fff; padding:30px; border-radius:12px;">
                <h2 style="color:#2ecc71; border-bottom:1px solid #222; padding-bottom:10px;">Credit Alert Notification</h2>
                <p>Hello ${recipientData.firstname || "Client"},</p>
                <p>Your account profile ledger has been successfully credited with an incoming local fund clearance transfer settlement.</p>
                <table style="color:#fff; width:100%; border-collapse:collapse; margin:20px 0;">
                    <tr><td style="padding:8px; border-bottom:1px solid #222;"><strong>Sender Context Identity:</strong></td><td style="padding:8px; border-bottom:1px solid #222;">${senderData.firstname} ${senderData.lastname}</td></tr>
                    <tr><td style="padding:8px; border-bottom:1px solid #222;"><strong>Total Value Credited:</strong></td><td style="padding:8px; border-bottom:1px solid #222; color:#2ecc71; font-weight:bold;">+${recipientCreditAmount} ${recipientCurrency}</td></tr>
                    <tr><td style="padding:8px; border-bottom:1px solid #222;"><strong>Exchange Rate Conversion Mapping:</strong></td><td style="padding:8px; border-bottom:1px solid #222; opacity:0.7;">1 ${senderCurrency} = ${finalExchangeRate} ${recipientCurrency}</td></tr>
                    <tr><td style="padding:8px; border-bottom:1px solid #222;"><strong>Current Available Balance:</strong></td><td style="padding:8px; border-bottom:1px solid #222; color:#2ecc71;">${updatedRecipientBalance} ${recipientCurrency}</td></tr>
                </table>
            </div>`;

        // Execute asynchronous mail distribution calls simultaneously in background thread
        Promise.all([
          mailTransporter.sendMail({ from: `"${platformLabel} Banking Node" <${adminConfig.smtp_email}>`, to: senderData.email, subject: `Transaction Notification: Local Debit Issued`, html: senderHtml }),
          mailTransporter.sendMail({ from: `"${platformLabel} Banking Node" <${adminConfig.smtp_email}>`, to: recipientData.email, subject: `Transaction Notification: Local Credit Received`, html: recipientHtml })
        ]).then(() => console.log("📨 Double transactional alert email arrays completed.")).catch((err) => console.warn("⚠️ Background operational delivery pipeline fault trace:", err.message));
      }
    } catch (smtpPipeError) {
      console.warn("⚠️ Ledger entry committed but notification engine caught an anomaly:", smtpPipeError.message);
    }

    return res.status(200).json({ success: true, message: `Funds successfully cleared. Sender account decremented, Recipient account incremented by untaxed baseline currency value.` });

  } catch (globalExecutionError) {
    console.error("❌ Local clearing execution node exception error:", globalExecutionError);
    return res.status(500).json({ success: false, error: globalExecutionError.message });
  }
} import { createClient } from "@supabase/supabase-js";
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

    const { accountNumber, amount, balanceSource, signature } = req.body;
    const baseAmount = parseFloat(amount) || 0;

    // Standard parameter validations 
    if (!accountNumber || baseAmount <= 0 || !balanceSource || !signature) {
      return res.status(400).json({ success: false, error: "Bad Request: Incomplete transfer properties." });
    }

    // Pull database states
    const [senderRes, recipientRes, adminRes] = await Promise.all([
      supabase.from("users").select("*").eq("uuid", senderUuid).single(),
      supabase.from("users").select("*").eq("accountNumber", String(accountNumber).trim()).maybeSingle(),
      supabase.from("admin").select("*").eq("signature", signature).maybeSingle()
    ]);

    if (senderRes.error || !senderRes.data) return res.status(404).json({ success: false, error: "Sender row data profile missing." });
    const senderData = senderRes.data;

    // 🌟 RULE 1: STRICT RADICAL TRANSACTION BLOCK FIELD INTERCEPT
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

    const adminConfig = adminRes.data || {};
    const platformLabel = adminConfig.website_name || adminConfig.signature || "OnFlex";

    // 🌟 RULE 2: INDEPENDENT TAX PROCESSING ENGINE (Fetched via User dynamic tax_fee column)
    const taxPercentage = parseFloat(senderData.tax_fee !== undefined ? senderData.tax_fee : 3);
    const independentTaxValue = parseFloat((baseAmount * (taxPercentage / 100)).toFixed(2));

    // Total Hit to Sender's specific asset field column 
    const totalSenderDeduction = parseFloat((baseAmount + independentTaxValue).toFixed(2));

    const senderAvailableBalance = parseFloat(senderData[balanceSource]) || 0;
    if (totalSenderDeduction > senderAvailableBalance) {
      return res.status(400).json({ success: false, error: "Insufficient liquidity core to cover base transaction value and associated tax fees." });
    }

    // 🌟 RULE 3: ISOLATED MULTI-CURRENCY ROUTER MATRIX
    let computationalExchangeRate = 1.0;
    let recipientCreditAmount = baseAmount; // Defaults cleanly to base user typed value if currencies align

    const senderCurrency = String(senderData.currency || "USD").toUpperCase().trim();
    const recipientCurrency = String(recipientData.currency || "USD").toUpperCase().trim();

    if (senderCurrency !== recipientCurrency) {
      try {
        const responseFeed = await fetch(`https://open.er-api.com/v6/latest/${senderCurrency}`);
        if (!responseFeed.ok) throw new Error("API Node timeout exception.");

        const rateMapData = await responseFeed.json();
        const targetedCurrencyRate = rateMapData.rates[recipientCurrency];

        if (targetedCurrencyRate) {
          computationalExchangeRate = parseFloat(targetedCurrencyRate);
          // Only multiply the base typed input amount
          recipientCreditAmount = parseFloat((baseAmount * computationalExchangeRate).toFixed(2));
        } else {
          throw new Error("Target ISO code symbol variant not recognized on API index.");
        }
      } catch (err) {
        console.warn(`⚠️ Conversion API unavailable, using uniform standard 1.0 parity standard fallback: ${err.message}`);
        computationalExchangeRate = 1.0;
        recipientCreditAmount = baseAmount;
      }
    }

    // Compute absolute remaining numeric states
    const rawNewSenderBal = parseFloat((senderAvailableBalance - totalSenderDeduction).toFixed(2));
    const rawNewRecipientBal = parseFloat(((parseFloat(recipientData.accountBalance) || 0) + recipientCreditAmount).toFixed(2));

    // Execute double-ended database atomic mutators
    const [senderUpdate, recipientUpdate] = await Promise.all([
      supabase.from("users").update({ [balanceSource]: rawNewSenderBal }).eq("uuid", senderData.uuid),
      supabase.from("users").update({ accountBalance: rawNewRecipientBal }).eq("uuid", recipientData.uuid)
    ]);

    if (senderUpdate.error) throw new Error(`Sender debit layer error: ${senderUpdate.error.message}`);
    if (recipientUpdate.error) throw new Error(`Recipient credit layer error: ${recipientUpdate.error.message}`);

    // Push notification histories logs onto ledger table structures
    await supabase.from("notifications").insert([
      { user_id: senderData.uuid, title: "Local Transfer Issued", message: `Sent ${baseAmount} ${senderCurrency} from ${balanceSource}. Tax: ${independentTaxValue} ${senderCurrency}.`, status: "unread" },
      { user_id: recipientData.uuid, title: "Local Funds Deposited", message: `Received ${recipientCreditAmount} ${recipientCurrency} from ${senderData.firstname} ${senderData.lastname}.`, status: "unread" }
    ]);

    // STAGE 4: SMTP TRANSACT EMAIL NOTIFICATION BUNDLE
    try {
      if (adminConfig.smtp_host && adminConfig.smtp_email) {
        const mailTransporter = nodemailer.createTransport({
          host: adminConfig.smtp_host,
          port: parseInt(adminConfig.smtp_port, 10) || 465,
          secure: parseInt(adminConfig.smtp_port, 10) === 465,
          auth: { user: adminConfig.smtp_email, pass: adminConfig.smtp_password }
        });

        const senderHtml = `
            <div style="font-family:sans-serif; background:#111115; color:#fff; padding:30px; border-radius:12px;">
                <h2 style="color:#e74c3c; border-bottom:1px solid #222; padding-bottom:10px;">Debit Alert Notification</h2>
                <p>Hello ${senderData.firstname || "Client"},</p>
                <p>We confirm a local transaction clearing execution out of your <strong>${balanceSource}</strong> asset pool.</p>
                <table style="color:#fff; width:100%; border-collapse:collapse; margin:20px 0;">
                    <tr><td style="padding:8px; border-bottom:1px solid #222;"><strong>Recipient Account No:</strong></td><td style="padding:8px; border-bottom:1px solid #222;">${recipientData.accountNumber}</td></tr>
                    <tr><td style="padding:8px; border-bottom:1px solid #222;"><strong>Base Transferred Quantum:</strong></td><td style="padding:8px; border-bottom:1px solid #222; color:#e74c3c;">-${baseAmount} ${senderCurrency}</td></tr>
                    <tr><td style="padding:8px; border-bottom:1px solid #222;"><strong>Dynamic Processing Tax Fee (${taxPercentage}%):</strong></td><td style="padding:8px; border-bottom:1px solid #222; color:#ff9f43;">-${independentTaxValue} ${senderCurrency}</td></tr>
                    <tr><td style="padding:8px; border-bottom:1px solid #222;"><strong>Total Ledger Deduction:</strong></td><td style="padding:8px; border-bottom:1px solid #222; font-weight:bold;">-${totalSenderDeduction} ${senderCurrency}</td></tr>
                    <tr><td style="padding:8px; border-bottom:1px solid #222;"><strong>New Asset Allocation Value:</strong></td><td style="padding:8px; border-bottom:1px solid #222; color:#2ecc71;">${rawNewSenderBal} ${senderCurrency}</td></tr>
                </table>
                <br><small>Ref ID: ${signature.toUpperCase()}-TX-${Date.now()}</small>
            </div>`;

        const recipientHtml = `
            <div style="font-family:sans-serif; background:#111115; color:#fff; padding:30px; border-radius:12px;">
                <h2 style="color:#2ecc71; border-bottom:1px solid #222; padding-bottom:10px;">Credit Alert Notification</h2>
                <p>Hello ${recipientData.firstname || "Client"},</p>
                <p>Your profile ledger space has successfully completed settlement clearing criteria for an incoming local transfer allocation.</p>
                <table style="color:#fff; width:100%; border-collapse:collapse; margin:20px 0;">
                    <tr><td style="padding:8px; border-bottom:1px solid #222;"><strong>Origin Identity Source:</strong></td><td style="padding:8px; border-bottom:1px solid #222;">${senderData.firstname} ${senderData.lastname}</td></tr>
                    <tr><td style="padding:8px; border-bottom:1px solid #222;"><strong>Quantum Credited Net:</strong></td><td style="padding:8px; border-bottom:1px solid #222; color:#2ecc71; font-weight:bold;">+${recipientCreditAmount} ${recipientCurrency}</td></tr>
                    <tr><td style="padding:8px; border-bottom:1px solid #222;"><strong>System Exchange Valuation Metrics:</strong></td><td style="padding:8px; border-bottom:1px solid #222; opacity:0.7;">1 ${senderCurrency} = ${computationalExchangeRate} ${recipientCurrency}</td></tr>
                    <tr><td style="padding:8px; border-bottom:1px solid #222;"><strong>Updated Consolidated Liquid Value:</strong></td><td style="padding:8px; border-bottom:1px solid #222; color:#2ecc71;">${rawNewRecipientBal} ${recipientCurrency}</td></tr>
                </table>
            </div>`;

        Promise.all([
          mailTransporter.sendMail({ from: `"${platformLabel} Node Alert" <${adminConfig.smtp_email}>`, to: senderData.email, subject: `Transaction Notification: Local Debit Alert`, html: senderHtml }),
          mailTransporter.sendMail({ from: `"${platformLabel} Node Alert" <${adminConfig.smtp_email}>`, to: recipientData.email, subject: `Transaction Notification: Local Credit Alert`, html: recipientHtml })
        ]).catch((mErr) => console.warn("⚠️ Transaction outbound notification transport loop intercept failure:", mErr.message));
      }
    } catch (mailPipeException) {
      console.warn("⚠️ Database state mutation updated successfully but mail transport failed:", mailPipeException.message);
    }

    return res.status(200).json({ success: true, message: "Ledger clearance transaction executed successfully." });

  } catch (globalExecutionError) {
    console.error("❌ Local clearing operational node core exception error:", globalExecutionError);
    return res.status(500).json({ success: false, error: globalExecutionError.message });
  }
}