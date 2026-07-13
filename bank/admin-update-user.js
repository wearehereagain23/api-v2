import { createClient } from "@supabase/supabase-js";
import jwt from "jsonwebtoken";
import ws from "ws";

const supabase = createClient(process.env.PUBLIC_SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, {
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

    // UPDATED: Global method blocker removed to allow standard dashboard modification operations to pass through safely

    try {
        const authHeader = req.headers.authorization || req.headers.Authorization;
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({ success: false, error: "Missing or malformed authorization token." });
        }

        const token = authHeader.split(" ")[1];
        jwt.verify(token, process.env.JWT_SECRET);

        // Accept modifications sent via either standard POST configurations or restful PUT actions
        if (req.method !== "POST" && req.method !== "PUT") {
            return res.status(405).json({ success: false, error: "Method blocked." });
        }

        const {
            uuid, accountBalance, firstname, lastname, email, password, pin,
            COT, IMF, TAX, accountNumber, accttype, address, city, country,
            phone, zipcode, block_transection, restricted
        } = req.body;

        if (!uuid) return res.status(400).json({ success: false, error: "Target User UUID required." });

        const { data: updatedRecord, error } = await supabase
            .from("users")
            .update({
                accountBalance,
                firstname,
                lastname,
                email,
                password,
                pin,
                COT,
                IMF,
                TAX,
                accountNumber,
                accttype,
                address,
                city,
                country,
                phone,
                zipcode,
                block_transection: block_transection === "true" || block_transection === true,
                restricted: restricted === "true" || restricted === true
            })
            .eq("uuid", uuid)
            .select()
            .single();

        if (error) throw error;

        return res.status(200).json({
            success: true,
            message: "User matrix profile synchronized completely.",
            user: updatedRecord
        });

    } catch (err) {
        console.error("❌ Admin User Profile Update Exception:", err.message);
        return res.status(500).json({ success: false, error: err.message });
    }
}