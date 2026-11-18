
const express = require("express");
const cors = require("cors");
const argon2 = require("argon2");
const crypto = require("crypto");
require("dotenv").config();

const app = express();

app.use(cors());
app.use(express.json());

// ==========================================
// HEALTH CHECK
// ==========================================

app.get("/", (req, res) => {
    res.json({
        status: "success",
        message: "Employee Authentication API is running"
    });
});

// ==========================================
// API KEY VERIFICATION MIDDLEWARE
// ==========================================

function verifyApiKey(req, res, next) {
    const apiKey = req.headers["x-api-key"];

    if (
        !process.env.API_SECRET ||
        apiKey !== process.env.API_SECRET
    ) {
        console.warn("API SECURITY: Unauthorized request rejected");

        return res.status(401).json({
            success: false,
            message: "Unauthorized request"
        });
    }

    next();
}

// ==========================================
// GENERATE EMPLOYEE INVITATION TOKEN
// ==========================================

app.post("/generate-invitation", verifyApiKey, (req, res) => {
    try {
        console.log("INVITATION: Generation request received");

        const invitationToken = crypto
            .randomBytes(32)
            .toString("hex");

        const tokenHash = crypto
            .createHash("sha256")
            .update(invitationToken)
            .digest("hex");

        console.log("INVITATION: Token generated successfully");

        res.json({
            success: true,
            invitationToken,
            tokenHash
        });

    } catch (error) {
        console.error(
            "INVITATION ERROR:",
            error.message
        );

        res.status(500).json({
            success: false,
            message: "Invitation token generation failed"
        });
    }
});

// ==========================================
// HASH INVITATION TOKEN
// ==========================================

app.post("/hash-invitation-token", verifyApiKey, (req, res) => {
    try {
        console.log("INVITATION: Token hashing request received");

        const { token } = req.body || {};

        if (!token || !/^[a-fA-F0-9]{64}$/.test(token)) {
            console.warn("INVITATION: Invalid token format");

            return res.status(400).json({
                success: false,
                message: "Invalid invitation token"
            });
        }

        const tokenHash = crypto
            .createHash("sha256")
            .update(token)
            .digest("hex");

        console.log("INVITATION: Token hashed successfully");

        res.json({
            success: true,
            tokenHash
        });

    } catch (error) {
        console.error(
            "TOKEN HASHING ERROR:",
            error.message
        );

        res.status(500).json({
            success: false,
            message: "Token hashing failed"
        });
    }
});

// ==========================================
// HASH EMPLOYEE PASSWORD
// ==========================================

app.post("/hash-password", verifyApiKey, async (req, res) => {
    try {
        console.log("PASSWORD HASHING: Request received");

        const { password } = req.body || {};

        if (!password || password.length < 12) {
            console.warn("PASSWORD HASHING: Invalid password input");

            return res.status(400).json({
                success: false,
                message: "Password must contain at least 12 characters"
            });
        }

        const passwordHash = await argon2.hash(password, {
            type: argon2.argon2id
        });

        console.log("PASSWORD HASHING: Completed successfully");

        res.json({
            success: true,
            passwordHash
        });

    } catch (error) {
        console.error(
            "PASSWORD HASHING ERROR:",
            error.message
        );

        res.status(500).json({
            success: false,
            message: "Password hashing failed"
        });
    }
});

// ==========================================
// VERIFY EMPLOYEE PASSWORD
// ==========================================

app.post("/verify-password", verifyApiKey, async (req, res) => {
    try {
        console.log("VERIFY-PASSWORD: Request received");

        const { password, passwordHash } = req.body || {};

        // Check whether both fields were received.
        console.log("VERIFY-PASSWORD: Password received:", !!password);
        console.log("VERIFY-PASSWORD: Hash received:", !!passwordHash);

        if (!password || !passwordHash) {
            console.warn("VERIFY-PASSWORD: Required fields missing");

            return res.status(400).json({
                success: false,
                message: "Password and hash are required"
            });
        }

        const authenticated = await argon2.verify(
            passwordHash,
            password
        );

        console.log(
            "VERIFY-PASSWORD: Verification completed:",
            authenticated
        );

        res.json({
            success: true,
            authenticated
        });

    } catch (error) {
        console.error(
            "VERIFY-PASSWORD ERROR:",
            error.message
        );

        res.status(400).json({
            success: false,
            message: "Password verification failed"
        });
    }
});

// ==========================================
// START SERVER
// ==========================================

const PORT = process.env.PORT || 3000;

app.listen(PORT, "0.0.0.0", () => {
    console.log(
        `Authentication API running on port ${PORT}`
    );
});
