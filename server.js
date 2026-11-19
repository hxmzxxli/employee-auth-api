
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const argon2 = require("argon2");
const crypto = require("crypto");
const { Resend } = require("resend");

const app = express();

const resend = new Resend(process.env.RESEND_API_KEY);

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
        console.error("INVITATION ERROR:", error.message);

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
        console.error("TOKEN HASHING ERROR:", error.message);

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

        if (
            typeof password !== "string" ||
            password.length < 12
        ) {
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
        console.error("PASSWORD HASHING ERROR:", error.message);

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

        console.log("VERIFY-PASSWORD: Password received:", !!password);
        console.log("VERIFY-PASSWORD: Hash received:", !!passwordHash);

        if (
            typeof password !== "string" ||
            typeof passwordHash !== "string" ||
            !password ||
            !passwordHash
        ) {
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
        console.error("VERIFY-PASSWORD ERROR:", error.message);

        res.status(400).json({
            success: false,
            message: "Password verification failed"
        });
    }
});

// ==========================================
// HTML ESCAPING HELPER
// ==========================================

function escapeHtml(value) {
    return String(value || "").replace(/[&<>"']/g, char => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
    })[char]);
}

// ==========================================
// SEND EMPLOYEE INVITATION EMAIL
// ==========================================

app.post("/send-invitation", verifyApiKey, async (req, res) => {
    try {
        console.log("EMAIL: Invitation request received");

        const {
            email,
            invitationUrl,
            employeeName
        } = req.body || {};

        // Validate required fields

        if (!email || !invitationUrl) {
            return res.status(400).json({
                success: false,
                message: "Email and invitation URL are required"
            });
        }

        // Validate email address

        const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

        if (
            typeof email !== "string" ||
            !emailPattern.test(email)
        ) {
            return res.status(400).json({
                success: false,
                message: "Invalid email address"
            });
        }

        // Validate invitation URL

        let parsedUrl;

        try {
            parsedUrl = new URL(invitationUrl);

            if (parsedUrl.protocol !== "https:") {
                throw new Error("HTTPS required");
            }

        } catch {
            return res.status(400).json({
                success: false,
                message: "Invalid invitation URL"
            });
        }

        // Prepare safe HTML values

        const safeName = escapeHtml(employeeName || "Employee");
        const safeUrl = escapeHtml(invitationUrl);

        // Send email using Resend

        const { data, error } = await resend.emails.send({

            from: "Employee Management <onboarding@resend.dev>",

            to: [email],

            subject: "Your Employee Account Invitation",

            html: `
                <!DOCTYPE html>
                <html>
                <body style="
                    font-family: Arial, sans-serif;
                    background-color: #f4f6f9;
                    padding: 30px;
                    color: #333;
                ">

                    <div style="
                        max-width: 550px;
                        margin: auto;
                        background: white;
                        padding: 30px;
                        border-radius: 10px;
                    ">

                        <h2 style="color: #2563eb;">
                            Welcome, ${safeName}!
                        </h2>

                        <p>
                            Your employee account has been created.
                        </p>

                        <p>
                            Please click the button below
                            to set up your password.
                        </p>

                        <div style="margin: 30px 0;">

                            <a href="${safeUrl}"
                               style="
                                   background-color: #2563eb;
                                   color: white;
                                   padding: 14px 24px;
                                   text-decoration: none;
                                   border-radius: 6px;
                                   display: inline-block;
                                   font-weight: bold;
                               ">
                                Set Up Your Account
                            </a>

                        </div>

                        <p style="font-size: 14px; color: #666;">
                            This invitation expires in 24 hours
                            and can only be used once.
                        </p>

                        <hr style="
                            border: none;
                            border-top: 1px solid #eee;
                        ">

                        <p style="font-size: 13px; color: #888;">
                            Regards,<br>
                            Employee Management Team
                        </p>

                    </div>

                </body>
                </html>
            `
        });

        // Handle Resend errors

        if (error) {
            console.error("RESEND ERROR:", error);

            return res.status(500).json({
                success: false,
                message: "Email delivery failed"
            });
        }

        console.log("EMAIL: Invitation sent successfully:", data.id);

        return res.json({
            success: true,
            message: "Invitation email sent successfully",
            id: data.id
        });

    } catch (error) {
        console.error("EMAIL ERROR:", error.message);

        return res.status(500).json({
            success: false,
            message: "Internal server error"
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
