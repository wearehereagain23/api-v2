import { createClient } from "@supabase/supabase-js";
import jwt from "jsonwebtoken";
import ws from "ws"; // Embedded Node.js WebSocket layer

// 1. ENVIRONMENT PROPERTIES SCHEMATICS
const SUPABASE_URL = process.env.PUBLIC_SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const JWT_SECRET = process.env.JWT_SECRET;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY || !JWT_SECRET) {
    throw new Error("CRITICAL CONFIGURATION ERROR: Environment token parameter configurations are unassigned inside properties.");
}

// Fixed client initialization incorporating ws options
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false },
    realtime: { transport: ws }
});

export default async function historyHandler(req, res) {
    // A. CORS & MULTI-METHOD CONTROL STRUCTURES
    const requestOrigin = req.headers.origin;
    if (requestOrigin) res.setHeader("Access-Control-Allow-Origin", requestOrigin);
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.setHeader("Access-Control-Allow-Credentials", "true");

    if (req.method === "OPTIONS") return res.status(200).end();
    if (req.method !== "GET") return res.status(405).json({ success: false, error: "Method blocked." });

    // B. AUTHORIZATION & SESSION TOKEN VERIFICATION MATRIX
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ success: false, error: "Access denied. Token missing." });
    }

    const token = authHeader.split(" ")[1];
    let decodedUser;
    try {
        decodedUser = jwt.verify(token, JWT_SECRET);
    } catch (err) {
        return res.status(403).json({ success: false, error: "Session token expired or corrupted." });
    }

    const userUuid = decodedUser.uuid;
    const signature = decodedUser.signature;

    if (!userUuid || !signature) {
        return res.status(400).json({ success: false, error: "Token claim configurations are structural nulls." });
    }

    try {
        // C. RETRIEVE ISOLATED HISTORICAL STREAM RECOGNIZING SIGNATURE BOUNDS
        const { data: historyRecords, error: historyDbError } = await supabase
            .from("history")
            .select("*")
            .eq("uuid", userUuid)
            .eq("signature", signature)
            .order("id", { ascending: false });

        if (historyDbError) {
            throw new Error(`Supabase infrastructure pipeline failure: ${historyDbError.message}`);
        }

        // D. TRANSLATE DATA SCHEMAS SAFELY TO MATCH FRONTEND COMPATIBILITY MATRIX
        const formattedData = (historyRecords || []).map(record => {
            let amountVal = parseFloat(record.amount || 0);

            // Adjust sign if transactionType is explicitly mapped to 'Debit' but arrives unsigned
            if (String(record.transactionType).toLowerCase().trim() === 'debit' && amountVal > 0) {
                amountVal = -amountVal;
            }

            return {
                id: record.id,
                uuid: record.uuid,
                signature: record.signature,
                name: record.name || "",
                description: record.description || "System Allocation Transfer",
                amount: amountVal,
                status: record.status || "success",
                date: record.date || "",
                withdrawFrom: record.withdrawFrom || "",
                bankName: record.bankName || "",
                created_at: record.created_at
            };
        });

        return res.status(200).json({
            success: true,
            data: formattedData
        });

    } catch (globalFaultException) {
        console.error("❌ Global transaction history engine failure:", globalFaultException);
        return res.status(500).json({
            success: false,
            error: globalFaultException.message || "Internal data ledger connection breakdown fault."
        });
    }
}