import { createClient } from "@supabase/supabase-js";
import jwt from "jsonwebtoken";
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

    // 2. Allow all HTTP methods your handlers use
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");

    // 3. Explicitly allow all your specific custom app headers
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, Accept, X-Action, X-Action-Phase, X-Transaction-Pin, X-User-UUID, X-Setting-Target, x-setting-target");

    // 4. Keep your credentials authentication layer active
    res.setHeader("Access-Control-Allow-Credentials", "true");

    // Handle preflight options request immediately
    if (req.method === "OPTIONS") {
        return res.status(200).end();
    }

    // UPDATED: Global method check removed from here to allow GET queries to process safely

    try {
        // Validate incoming token credentials cleanly with safety checks
        const authHeader = req.headers.authorization || req.headers.Authorization;
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({ success: false, error: "Administrative security clearance missing." });
        }

        const token = authHeader.split(" ")[1];
        const decoded = jwt.verify(token, JWT_SECRET);

        // -------------------------------------------------------------------------
        // PATHWAY 1: PULL SETTINGS META DATA
        // -------------------------------------------------------------------------
        if (req.method === "GET") {
            const { data: adminSettings, error: queryError } = await supabase
                .from("admin")
                .select("id, smtp_email, smtp_password, signature, address")
                .eq("id", decoded.adminId)
                .maybeSingle();

            if (queryError) throw queryError;
            if (!adminSettings) {
                return res.status(404).json({ success: false, error: "Administrative workspace records not found." });
            }

            return res.status(200).json({ success: true, settings: adminSettings });
        }

        // -------------------------------------------------------------------------
        // PATHWAY 2: UPDATE STRICTLY ADDRESS ENTRY VALUE
        // -------------------------------------------------------------------------
        if (req.method === "POST") {
            const { address } = req.body;

            const { data: updatedSettings, error: updateError } = await supabase
                .from("admin")
                .update({ address: address }) // Modifies only the address entry parameters
                .eq("id", decoded.adminId)
                .select()
                .single();

            if (updateError) throw updateError;

            return res.status(200).json({ success: true, settings: updatedSettings });
        }

        return res.status(405).json({ success: false, error: "Method implementation target signature blocked." });

    } catch (err) {
        console.error("❌ Admin Settings Exception Node:", err.message);
        return res.status(500).json({ success: false, error: err.message });
    }
}