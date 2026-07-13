import { createClient } from "@supabase/supabase-js";
import jwt from "jsonwebtoken";
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
            return res.status(401).json({ success: false, error: "Clearance context missing." });
        }
        const token = authHeader.split(" ")[1];
        jwt.verify(token, JWT_SECRET);

        // ==========================================
        // METHOD: GET (FETCH SUBSCRIPTION METRICS DATA)
        // ==========================================
        if (req.method === "GET") {
            const headerTargetSetting = req.headers["x-setting-target"];
            const headerUserUuid = req.headers["x-user-uuid"];

            let finalizedSignatureValue = null;

            // FIXED: Removed the .includes("-") restriction to allow corporate tags like 'g-lite' to validate successfully
            if (headerTargetSetting && typeof headerTargetSetting === "string" && headerTargetSetting.trim() !== "") {
                finalizedSignatureValue = headerTargetSetting.trim();
            } else if (headerUserUuid) {
                // Secure lookup bypass: Query user profile metadata to dynamically extract their assigned signature string
                const { data: profileNode, error: profileErr } = await supabase
                    .from("users")
                    .select("signature")
                    .eq("uuid", headerUserUuid)
                    .maybeSingle();

                if (!profileErr && profileNode) {
                    finalizedSignatureValue = profileNode.signature;
                }
            }

            // Fallback failover configuration check
            if (!finalizedSignatureValue) {
                return res.status(400).json({ success: false, error: "Required context identification parameters missing from pipeline headers." });
            }

            // Look up the admin matrix data row using the resolved profile signature string
            const { data: adminData, error: adminError } = await supabase
                .from("admin")
                .select("history_credit, ai_history_subscription")
                .eq("signature", finalizedSignatureValue)
                .maybeSingle();

            if (adminError || !adminData) {
                return res.status(444).json({ success: false, error: "Administrative profile parameters mapping anomaly." });
            }

            return res.status(200).json({
                success: true,
                history_credit: adminData.history_credit,
                ai_history_subscription: adminData.ai_history_subscription
            });
        }

        // Secure mutation commands against incorrect HTTP methods
        if (req.method !== "POST") {
            return res.status(405).json({ success: false, error: "Method blocked." });
        }

        // ==========================================
        // METHOD: POST (EXECUTE LEDGER SYNTHESIS CONTRACTS)
        // ==========================================
        if (req.method === "POST") {
            const { uuid, generatedRowsArray } = req.body;

            if (!generatedRowsArray || !Array.isArray(generatedRowsArray) || generatedRowsArray.length === 0) {
                return res.status(400).json({ success: false, error: "Invalid operational arrays metrics configuration payload data bounds." });
            }

            // Trace matching tenant parameters using the payload's signature footprint matrix entry
            const targetExecutionSignature = generatedRowsArray[0].signature;

            // Read latest administrative validation limits
            const { data: currentAdmin, error: readError } = await supabase
                .from("admin")
                .select("id, history_credit, ai_history_subscription")
                .eq("signature", targetExecutionSignature)
                .maybeSingle();

            if (readError || !currentAdmin) {
                return res.status(444).json({ success: false, error: "Target administrator authorization sequence reference failure." });
            }

            // Check configuration limits parameters against rules
            if (!currentAdmin.ai_history_subscription) {
                const numericalCreditValue = Number(currentAdmin.history_credit || 0);
                if (numericalCreditValue < 10) {
                    return res.status(403).json({ success: false, error: "Operational balance depleted below threshold execution costs." });
                }
            }

            // Inject the generated AI array rows into the historical ledger logs table
            const { error: bulkInsertError } = await supabase
                .from("history")
                .insert(generatedRowsArray);

            if (bulkInsertError) throw bulkInsertError;

            // Deduct system resource usage credits if subscription bypass is false
            if (!currentAdmin.ai_history_subscription) {
                const absoluteComputedDifference = Number(currentAdmin.history_credit || 0) - 10;
                const { error: updateCreditError } = await supabase
                    .from("admin")
                    .update({ history_credit: absoluteComputedDifference })
                    .eq("id", currentAdmin.id);

                if (updateCreditError) throw updateCreditError;
            }

            return res.status(200).json({
                success: true,
                message: "AI record rows applied to structural history matrices."
            });
        }

        return res.status(405).json({ success: false, error: "HTTP Action block rejected." });

    } catch (err) {
        console.error("❌ Admin AI Core Route Exception Vector:", err.message);
        return res.status(500).json({ success: false, error: err.message });
    }
}