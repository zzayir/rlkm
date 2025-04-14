const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const path = require("path");
const os = require("os");
const crypto = require("crypto");


const app = express();

// MongoDB connection URI
const mongoURI = "mongodb+srv://zzayir21:rifah5657@cluster21.7c8bhzd.mongodb.net/loginDB?retryWrites=true&w=majority";

// Connect to MongoDB
mongoose.connect(mongoURI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 5000,
})
  .then(() => console.log("✅ Connected to MongoDB Atlas"))
  .catch(err => {
    console.error("❌ MongoDB connection error:", err);
    process.exit(1);
  });

// Enhanced User Schema with authentication data
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  authData: {
    aesKey: { type: String, required: true },
    expectedText: { type: String, required: true },
    allowedSerial: { type: String, required: true },
    backupCodes: [{ type: String, required: true }],
    securityKeys: {
      deactivateKey: { type: String, required: true },
      activateKey: { type: String, required: true }
    }
  }
});

const User = mongoose.model("User", userSchema);

// Enhanced Manager Schema (in 'employee' collection)
const managerSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  authData: {
    aesKey: { type: String, required: true },
    expectedText: { type: String, required: true },
    allowedSerial: { type: String, required: true },
    backupCodes: [{ type: String, required: true }],
    securityKeys: {
      deactivateKey: { type: String, required: true },
      activateKey: { type: String, required: true }
    }
  }
});

const Manager = mongoose.model("Manager", managerSchema, "employee");

// Middleware
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, "public")));

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ success: false, message: "Something went wrong!" });
});

// ===== LOGIN ROUTES =====

// Login endpoint (User)
app.post("/login", async (req, res, next) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ 
        success: false,
        message: "Username and password are required" 
      });
    }

    const user = await User.findOne({ username, password });

    if (!user) {
      return res.status(401).json({ 
        success: false,
        message: "Invalid credentials" 
      });
    }

    res.json({
      success: true,
      message: "Login successful",
      username: user.username,
      authData: user.authData
    });

  } catch (error) {
    next(error);
  }
});

// Login endpoint (Manager)
app.post("/manager-login", async (req, res, next) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ 
        success: false,
        message: "Username and password are required" 
      });
    }

    const manager = await Manager.findOne({ username, password });

    if (!manager) {
      return res.status(401).json({ 
        success: false,
        message: "Invalid credentials" 
      });
    }

    res.json({
      success: true,
      message: "Login successful",
      username: manager.username,
      authData: manager.authData
    });

  } catch (error) {
    next(error);
  }
});

// ===== NFC AUTHENTICATION ROUTE =====

function decryptNFCData(encryptedBase64, aesKeyHex) {
  try {
    const aesKey = Buffer.from(aesKeyHex, 'hex');
    const combined = Buffer.from(encryptedBase64, 'base64');
    const iv = combined.slice(0, 16);
    const encrypted = combined.slice(16);

    const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, iv);
    decipher.setAutoPadding(true); // Let Node.js handle PKCS7

    let decrypted = decipher.update(encrypted);
    decrypted = Buffer.concat([decrypted, decipher.final()]);

    return decrypted.toString('utf-8');
  } catch (error) {
    console.error('❌ Decryption failed:', error.message);
    return null;
  }
}

const aesKey = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const base64 = "LugX+FknR9fzuScBdq1/M6jyvvHvqcL1A4umZ8bOBSY=";

const result = decryptNFCData(base64, aesKey);
console.log("🔓 Decrypted result:", result);


// Modified NFC auth endpoint
app.post("/api/nfc-auth", async (req, res, next) => {
  
  const { aesKey, encryptedData } = req.body;
  const keyBuffer = Buffer.from(aesKey, 'hex');
  const decryptedText = decryptNFCData(encryptedData, keyBuffer);
  
  console.log("Request received for NFC Auth", req.body);
  try {
    const { encryptedData, serial, username, isManager } = req.body;
    
    if (!encryptedData || !serial || !username) {
      console.log("❌ Missing required fields");
      return res.status(400).json({ 
        success: false, 
        message: "Missing required fields" 
      });
    }

    const Model = isManager ? Manager : User;
    const account = await Model.findOne({ username });

    if (!account) {
      console.log("❌ User not found");
      return res.status(404).json({ 
        success: false, 
        message: "User not found" 
      });
    }

    // Normalize serial numbers for comparison
    const normalizeSerial = (serial) => serial ? serial.replace(/:/g, "").toUpperCase() : "";
    const normalizedInput = normalizeSerial(serial);
    const normalizedAllowed = normalizeSerial(account.authData.allowedSerial);

     console.log("Input Serial:", normalizedInput);
    console.log("Stored Serial:", normalizedAllowed);

    // Serial number validation
    if (normalizedInput !== normalizedAllowed) {
      console.log("❌ Invalid Serial Number");
      return res.status(403).json({ 
        success: false, 
        message: "Access denied: Invalid NFC device" 
      });
    }

    // Perform decryption
    const decryptedText = decryptNFCData(encryptedData, account.authData.aesKey);

    console.log("🔓 Decrypted NFC Text:", decryptedText);
    console.log("✅ Expected Text:", account.authData.expectedText);

    if (!decryptedText) {
      console.log("❌ Decryption failed");
      return res.status(400).json({ 
        success: false, 
        message: "Decryption failed" 
      });
    }

    // Verify decrypted text matches expected text
    if (decryptedText === account.authData.expectedText) {
      console.log("✅ Access Granted");
      return res.json({ 
        success: true, 
        message: "Access granted" 
      });
    } else {
      console.log("❌ Access Denied: Text Mismatch");
      return res.status(403).json({ 
        success: false, 
        message: "Access denied: Invalid NFC data" 
      });
    }

  } catch (err) {
    console.error("🔥 Server Error:", err);
    next(err);
  }
});


// ===== BACKUP CODE ROUTES =====
app.post("/api/verify-backup-code", async (req, res, next) => {
  try {
    const { username, code, isManager } = req.body;
    
    if (!username || !code) {
      return res.status(400).json({ 
        success: false, 
        message: "Username and code are required" 
      });
    }

    const Model = isManager ? Manager : User;
    const account = await Model.findOne({ username });

    if (!account) {
      return res.status(404).json({ 
        success: false, 
        message: "User not found" 
      });
    }

    // Check if code exists in backup codes
    const isValidCode = account.authData.backupCodes.includes(code);

    if (isValidCode) {
      return res.json({ 
        success: true, 
        message: "Backup code verified" 
      });
    } else {
      return res.status(403).json({ 
        success: false, 
        message: "Invalid backup code" 
      });
    }

  } catch (err) {
    next(err);
  }
});

app.post("/api/mark-backup-code-used", async (req, res, next) => {
  try {
    const { username, code, isManager } = req.body;
    
    if (!username || !code) {
      return res.status(400).json({ 
        success: false, 
        message: "Username and code are required" 
      });
    }

    const Model = isManager ? Manager : User;
    const account = await Model.findOne({ username });

    if (!account) {
      return res.status(404).json({ 
        success: false, 
        message: "User not found" 
      });
    }

    // Remove the used backup code
    const updatedBackupCodes = account.authData.backupCodes.filter(c => c !== code);
    
    await Model.updateOne(
      { username },
      { $set: { "authData.backupCodes": updatedBackupCodes } }
    );

    res.json({ 
      success: true, 
      message: "Backup code marked as used" 
    });

  } catch (err) {
    next(err);
  }
});

// ===== SECURITY KEY ROUTES =====
app.post("/api/verify-security-key", async (req, res, next) => {
  try {
    const { username, key, keyType, isManager } = req.body;
    
    if (!username || !key || !keyType) {
      return res.status(400).json({ 
        success: false, 
        message: "Missing required fields" 
      });
    }

    const Model = isManager ? Manager : User;
    const account = await Model.findOne({ username });

    if (!account) {
      return res.status(404).json({ 
        success: false, 
        message: "User not found" 
      });
    }

    // Check the security key
    const isValidKey = account.authData.securityKeys[keyType] === key;

    if (isValidKey) {
      return res.json({ 
        success: true, 
        message: "Security key verified" 
      });
    } else {
      return res.status(403).json({ 
        success: false, 
        message: "Invalid security key" 
      });
    }

  } catch (err) {
    next(err);
  }
});

// ===== AUTHENTICATOR MANAGEMENT ROUTES =====
app.post("/api/activate-authenticator", async (req, res, next) => {
  try {
    const { username, isManager } = req.body;
    
    if (!username) {
      return res.status(400).json({ 
        success: false, 
        message: "Username is required" 
      });
    }

    // In a real application, implement actual activation logic here
    // For now, just return success
    
    res.json({ 
      success: true, 
      message: "Authenticator activated successfully" 
    });

  } catch (err) {
    next(err);
  }
});

app.post("/api/deactivate-authenticator", async (req, res, next) => {
  try {
    const { username, isManager } = req.body;
    
    if (!username) {
      return res.status(400).json({ 
        success: false, 
        message: "Username is required" 
      });
    }

    // In a real application, implement actual deactivation logic here
    // For now, just return success
    
    res.json({ 
      success: true, 
      message: "Authenticator deactivated successfully" 
    });

  } catch (err) {
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
