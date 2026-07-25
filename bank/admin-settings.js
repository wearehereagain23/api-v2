import { createClient } from "@supabase/supabase-js";
import ws from "ws";

const SUPABASE_URL = process.env.PUBLIC_SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false },
    realtime: { transport: ws }
});

export default async function handler(req, res) {
    const requestOrigin = req.headers.origin;
    if (requestOrigin) {
        res.setHeader("Access-Control-Allow-Origin", requestOrigin);
    }

    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, Accept, X-Signature, x-signature");
    res.setHeader("Access-Control-Allow-Credentials", "true");

    if (req.method === "OPTIONS") {
        return res.status(200).end();
    }

    // Extract signature from headers, query string, or body
    const signature =
        req.headers["x-signature"] ||
        req.headers["X-Signature"] ||
        req.query.signature ||
        (req.body && req.body.signature);

    if (!signature) {
        return res.status(401).json({ success: false, error: "Administrative signature is required." });
    }

    try {
        // -------------------------------------------------------------------------
        // METHOD: GET -> Fetch Admin Deployed Date & Current Address
        // -------------------------------------------------------------------------
        if (req.method === "GET") {
            const { data: adminData, error: adminError } = await supabase
                .from("admin")
                .select("deployed_date, address")
                .eq("signature", signature)
                .maybeSingle();

            if (adminError) {
                throw new Error(`Database fetch error: ${adminError.message}`);
            }

            if (!adminData) {
                return res.status(403).json({ success: false, error: "Invalid administrative signature verification signature." });
            }

            return res.status(200).json({
                success: true,
                data: {
                    expiringDate: adminData.deployed_date || "N/A",
                    address: adminData.address || ""
                }
            });
        }

        // -------------------------------------------------------------------------
        // METHOD: POST -> Update Admin Address Field
        // -------------------------------------------------------------------------
        if (req.method === "POST") {
            const { address } = req.body || {};

            if (address === undefined || address === null) {
                return res.status(400).json({ success: false, error: "Target address payload is required." });
            }

            // Verify admin existence by signature before updating
            const { data: adminRecord, error: verifyError } = await supabase
                .from("admin")
                .select("id")
                .eq("signature", signature)
                .maybeSingle();

            if (verifyError || !adminRecord) {
                return res.status(403).json({ success: false, error: "Invalid administrative signature verification signature." });
            }

            const { data: updatedAdmin, error: updateError } = await supabase
                .from("admin")
                .update({ address: address.trim() })
                .eq("id", adminRecord.id)
                .select("deployed_date, address")
                .single();

            if (updateError) {
                throw new Error(`Failed to update administrative settings: ${updateError.message}`);
            }

            return res.status(200).json({
                success: true,
                message: "Administrative address updated successfully.",
                data: {
                    expiringDate: updatedAdmin.deployed_date || "N/A",
                    address: updatedAdmin.address || ""
                }
            });
        }

        return res.status(405).json({ success: false, error: "HTTP Method not allowed." });

    } catch (err) {
        console.error("❌ Admin Settings Gateway Fault:", err.message);
        return res.status(500).json({ success: false, error: err.message || "Internal Service Connectivity Fault." });
    }
}