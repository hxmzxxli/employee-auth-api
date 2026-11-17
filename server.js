
const express = require("express");
const cors = require("cors");
const argon2 = require("argon2");
require("dotenv").config();

const app = express();

app.use(cors());
app.use(express.json());

// Health check
app.get("/", (req, res) => {
    res.json({
        status: "success",
        message: "Employee Authentication API is running"
    });
});

// API key verification middleware
function verifyApiKey(req, res, next) {
    const apiKey = req.headers["x-api-key"];

    if (!process.env.API_SECRET ||
        apiKey !== process.env.API_SECRET) {
        return res.status(401).json({
            success: false,
            message: "Unauthorized request"
        });
    }

    next();
}

// Password hashing
app.post("/hash-password", verifyApiKey, async (req, res) => {
    try {
        const { password } = req.body;

        if (!password || password.length < 12) {
            return res.status(400).json({
                success: false,
                message: "Password must contain at least 12 characters"
            });
        }

        const passwordHash = await argon2.hash(password, {
            type: argon2.argon2id
        });

        res.json({
            success: true,
            passwordHash
        });

    } catch (error) {
        console.error("Hashing error:", error.message);

        res.status(500).json({
            success: false,
            message: "Password hashing failed"
        });
    }
});

// Password verification
app.post("/verify-password", verifyApiKey, async (req, res) => {
    try {
        const { password, passwordHash } = req.body;

        if (!password || !passwordHash) {
            return res.status(400).json({
                success: false,
                message: "Password and hash are required"
            });
        }

        const authenticated = await argon2.verify(
            passwordHash,
            password
        );

        res.json({
            success: true,
            authenticated
        });

    } catch (error) {
        console.error("Verification error:", error.message);

        res.status(400).json({
            success: false,
            message: "Password verification failed"
        });
    }
});

// Start server
const PORT = process.env.PORT || 3000;

app.listen(PORT, "0.0.0.0", () => {
    console.log(`Authentication API running on port ${PORT}`);
});
