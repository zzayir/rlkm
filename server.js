const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const path = require("path");
const os = require("os");
const crypto = require("crypto");

const app = express();

// MongoDB connection URI - Consider using environment variables for sensitive data
const mongoURI = "mongodb+srv://zzayir21:rifah5657@cluster21.7c8bhzd.mongodb.net/loginDB?retryWrites=true&w=majority";

// AES-256-CBC decryption function with error handling
function decrypt(encryptedBase64, key, iv) {
  try {
    const decipher = crypto.createDecipheriv(
      "aes-256-cbc",
      Buffer.from(key, "utf-8"),
      Buffer.from(iv, "utf-8")
    );
    let decrypted = decipher.update(encryptedBase64, "base64", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
  } catch (err) {
    console.error("Decryption error:", err);
    return null;
  }
}

// Connect to MongoDB with updated options
mongoose.connect(mongoURI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 5000, // Timeout after 5s instead of 30s
})
  .then(() => console.log("✅ Connected to MongoDB Atlas"))
  .catch(err => {
    console.error("❌ MongoDB connection error:", err);
    process.exit(1); // Exit process if DB connection fails
  });

// User Schema with required fields
const userSchema = new mongoose.Schema({
  username: { type: String, required: true },
  password: { type: String, required: true },
  aesKey: { type: String, required: true },
  expectedText: { type: String, required: true },
  allowedSerial: { type: String, required: true }
});

const User = mongoose.model("User", userSchema);

// Manager Schema (in 'employee' collection)
const managerSchema = new mongoose.Schema({
  username: { type: String, required: true },
  password: { type: String, required: true },
  aesKey: { type: String, required: true },
  expectedText: { type: String, required: true },
  allowedSerial: { type: String, required: true }
});

const Manager = mongoose.model("Manager", managerSchema, "employee");

// Middleware
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, "public")));

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: "Something went wrong!" });
});

// ===== LOGIN ROUTES =====

// Login endpoint (User)
app.post("/login", async (req, res, next) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ message: "Username and password are required" });
    }

    const user = await User.findOne({ username, password });

    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    res.json({
      message: "Login successful",
      username: user.username,
      role: "user",
      aesKey: user.aesKey,
      expectedText: user.expectedText,
      allowedSerial: user.allowedSerial
    });

  } catch (error) {
    next(error); // Pass errors to the error-handling middleware
  }
});

// Login endpoint (Manager)
app.post("/manager-login", async (req, res, next) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ message: "Username and password are required" });
    }

    const manager = await Manager.findOne({ username, password });

    if (!manager) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    res.json({
      message: "Login successful",
      username: manager.username,
      role: "manager",
      aesKey: manager.aesKey,
      expectedText: manager.expectedText,
      allowedSerial: manager.allowedSerial
    });

  } catch (error) {
    next(error);
  }
});

// ===== NFC AUTHENTICATION ROUTE =====
const rateLimit = require('express-rate-limit');

// Add rate limiting to prevent brute force attacks
const nfcAuthLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each IP to 10 requests per windowMs
  message: 'Too many authentication attempts, please try again later'
});

app.post("/api/nfc-auth", nfcAuthLimiter, async (req, res, next) => {
  try {
    // Validate session first (if using session auth)
    if (!req.session.user) {
      return res.status(401).json({ 
        success: false, 
        message: "Session expired. Please login again." 
      });
    }

    const { encryptedData, serial } = req.body;
    
    // Enhanced input validation
    if (!encryptedData || !encryptedData.match(/^[A-Za-z0-9+/=]+$/)) {
      return res.status(400).json({ 
        success: false, 
        message: "Invalid encrypted data format" 
      });
    }

    if (!serial || typeof serial !== 'string') {
      return res.status(400).json({ 
        success: false, 
        message: "Invalid serial number format" 
      });
    }

    // Get user from session instead of request body for better security
    const { username, isManager } = req.session.user;
    const Model = isManager ? Manager : User;
    
    // Find account with projection to only get necessary fields
    const account = await Model.findOne(
      { username },
      { aesKey: 1, expectedText: 1, allowedSerial: 1 }
    ).lean();

    if (!account) {
      console.warn(`NFC Auth attempt for non-existent user: ${username}`);
      return res.status(404).json({ 
        success: false, 
        message: "Authentication failed" // Generic message for security
      });
    }

    // In production, you should retrieve this from the database per user
    const iv = "0000000000000000"; 
    
    // Add timing-safe comparison for security
    const decryptedText = decrypt(encryptedData, account.aesKey, iv);
    const isTextValid = decryptedText === account.expectedText;
    const isSerialValid = serial === account.allowedSerial;

    // Log the attempt (without sensitive data)
    console.log(`NFC Auth attempt for ${username} - ` +
      `Serial match: ${isSerialValid}, Text match: ${isTextValid}`);

    if (isTextValid && isSerialValid) {
      // Update last login time
      await Model.updateOne(
        { username },
        { $set: { lastLogin: new Date() } }
      );
      
      return res.json({ 
        success: true, 
        message: "Access granted",
        // Include any additional non-sensitive data needed by frontend
        userData: {
          username,
          role: isManager ? 'manager' : 'user'
        }
      });
    } else {
      return res.status(403).json({ 
        success: false, 
        message: "Authentication failed" // Generic message for security
      });
    }

  } catch (err) {
    console.error('NFC Auth Error:', {
      error: err.message,
      stack: err.stack,
      body: { 
        encryptedData: req.body.encryptedData ? '***REDACTED***' : null,
        serial: req.body.serial 
      },
      user: req.session?.user
    });
    
    // Send generic error message to client
    res.status(500).json({ 
      success: false, 
      message: "An error occurred during authentication" 
    });
    
    // Still call next(err) for your error handling middleware
    next(err); 
  }
});

// ====== HELPER: Get Local IP ======
function getLocalIP() {
  try {
    const interfaces = os.networkInterfaces();
    for (let name in interfaces) {
      for (let iface of interfaces[name]) {
        if (iface.family === "IPv4" && !iface.internal) {
          return iface.address;
        }
      }
    }
    return "localhost";
  } catch (err) {
    console.error("Error getting local IP:", err);
    return "localhost";
  }
}

// ====== START SERVER ======
const PORT = process.env.PORT || 3010;
const server = app.listen(PORT, "0.0.0.0", () => {
  const localIP = getLocalIP();
  console.log(`\n✅ Server running at:`);
  console.log(`👉 PC:     http://localhost:${PORT}`);
  console.log(`👉 Mobile: http://${localIP}:${PORT}\n`);
});

// Handle unhandled promise rejections
process.on("unhandledRejection", (err) => {
  console.error("Unhandled Rejection:", err);
  server.close(() => process.exit(1));
});

// Handle uncaught exceptions
process.on("uncaughtException", (err) => {
  console.error("Uncaught Exception:", err);
  server.close(() => process.exit(1));
});
