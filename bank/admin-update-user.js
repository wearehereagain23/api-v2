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

    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, Accept, X-Action, X-Action-Phase, X-Transaction-Pin, X-User-UUID, X-Setting-Target, x-setting-target");
    res.setHeader("Access-Control-Allow-Credentials", "true");

    if (req.method === "OPTIONS") {
        return res.status(200).end();
    }

    try {
        const authHeader = req.headers.authorization || req.headers.Authorization;
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({ success: false, error: "Missing or malformed authorization token." });
        }

        const token = authHeader.split(" ")[1];
        try {
            jwt.verify(token, process.env.JWT_SECRET);
        } catch (jwtErr) {
            return res.status(401).json({ success: false, error: `Authentication Failed: ${jwtErr.message}` });
        }

        if (req.method !== "POST" && req.method !== "PUT") {
            return res.status(405).json({ success: false, error: "Method blocked." });
        }
        jwt.verify(token, process.env.JWT_SECRET);

        if (req.method !== "POST" && req.method !== "PUT") {
            return res.status(405).json({ success: false, error: "Method blocked." });
        }

        // Destructure all full operational identity matrix fields
        const {
            id, uuid, accountBalance, accountTypeBalance, firstname, middlename, lastname,
            email, password, pin, accountNumber, currency, COT, IMF, TAX, accttype,
            address, city, country, phone, zipcode, dateOfBirth, gender, occupation,
            kinname, tiers, tax_fee, fixedDate, block_transection, restricted,
            transferAccess, activeuser
        } = req.body;

        const targetId = id || req.query.id;
        const targetUuid = uuid || req.body.uuid;

        if (!targetId && !targetUuid) {
            return res.status(400).json({ success: false, error: "Target User ID or UUID is required." });
        }

        // Parse boolean and numeric schema types cleanly
        const parsed2fa = req.body["2fa"] === "true" || req.body["2fa"] === true;
        const parsedBlockTransaction = block_transection === "true" || block_transection === true;
        const parsedRestricted = restricted === "true" || restricted === true;
        const parsedTransferAccess = transferAccess === "true" || transferAccess === true;
        const parsedActiveUser = activeuser === "true" || activeuser === true;
        const parsedTaxFee = tax_fee !== undefined && tax_fee !== null ? Number(tax_fee) : 3;

        // Build Supabase update query context dynamically based on identifier present
        let query = supabase.from("users").update({
            accountBalance,
            accountTypeBalance,
            firstname,
            middlename,
            lastname,
            email,
            password,
            pin,
            accountNumber,
            currency,
            COT,
            IMF,
            TAX,
            accttype,
            address,
            city,
            country,
            phone,
            zipcode,
            dateOfBirth,
            gender,
            occupation, // mapped correctly to database field
            kinname,
            tiers,
            tax_fee: parsedTaxFee,
            fixedDate,
            "2fa": parsed2fa,
            block_transection: parsedBlockTransaction,
            restricted: parsedRestricted,
            transferAccess: parsedTransferAccess,
            activeuser: parsedActiveUser
        });

        if (targetId) {
            query = query.eq("id", targetId);
        } else {
            query = query.eq("uuid", targetUuid);
        }

        const { data: updatedRecord, error } = await query.select().single();

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