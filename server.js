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

// Optimized decryption function
function decryptNFCData(encryptedBase64, aesKeyHex) {
  try {
    // Validate inputs first
    if (!encryptedBase64 || !aesKeyHex) {
      console.error('Missing required parameters');
      return null;
    }

    // Pre-validate Base64 (faster fail)
    if (!/^[A-Za-z0-9+/=]+$/.test(encryptedBase64)) {
      console.error('Invalid Base64 format');
      return null;
    }

    // Convert hex key to Buffer (sync operation)
    const aesKey = Buffer.from(aesKeyHex, 'hex');
    if (aesKey.length !== 32) {
      console.error('Invalid AES key length');
      return null;
    }

    // Decode Base64 and extract IV/data in one operation
    const combined = Buffer.from(encryptedBase64, 'base64');
    if (combined.length < 32) { // Minimum 16 IV + 16 encrypted
      console.error('Encrypted data too short');
      return null;
    }

    const iv = combined.subarray(0, 16); // Faster than slice
    const encrypted = combined.subarray(16);

    // Create and configure decipher
    const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, iv);
    decipher.setAutoPadding(false); // Handle padding manually for better performance

    // Single-pass decryption
    let decrypted = Buffer.concat([
      decipher.update(encrypted),
      decipher.final()
    ]);

    // Manual PKCS7 unpadding (faster than auto-padding)
    const padLength = decrypted[decrypted.length - 1];
    if (padLength <= 0 || padLength > 16) {
      console.error('Invalid padding');
      return null;
    }
    
    decrypted = decrypted.subarray(0, decrypted.length - padLength);
    return decrypted.toString('utf-8');
  } catch (error) {
    console.error('Decryption failed:', error.message);
    return null;
  }
}

// Optimized NFC auth endpoint
app.post("/api/nfc-auth", async (req, res, next) => {
  const startTime = process.hrtime(); // For performance measurement
  
  try {
    const { encryptedData, serial, username, isManager } = req.body;
    
    // Fast validation first
    if (!encryptedData || !serial || !username) {
      console.log('Fast validation failed');
      return res.status(400).json({ 
        success: false, 
        message: "Missing required fields",
        processingTime: `${process.hrtime(startTime)[1] / 1000000}ms`
      });
    }

    // Parallelize database lookup and decryption
    const [account, decryptedText] = await Promise.all([
      (isManager ? Manager : User).findOne({ username }).lean(),
      decryptNFCData(encryptedData, isManager 
        ? (await Manager.findOne({ username }).select('authData.aesKey').lean())?.authData?.aesKey
        : (await User.findOne({ username }).select('authData.aesKey').lean())?.authData?.aesKey
    ]);

    if (!account) {
      return res.status(404).json({ 
        success: false, 
        message: "User not found",
        processingTime: `${process.hrtime(startTime)[1] / 1000000}ms`
      });
    }

    // Fast serial comparison
    const normalizedInput = serial.replace(/:/g, "").toUpperCase();
    if (normalizedInput !== account.authData.allowedSerial.replace(/:/g, "").toUpperCase()) {
      return res.status(403).json({ 
        success: false, 
        message: "Access denied: Invalid NFC device",
        processingTime: `${process.hrtime(startTime)[1] / 1000000}ms`
      });
    }

    if (!decryptedText) {
      return res.status(400).json({ 
        success: false, 
        message: "Decryption failed",
        processingTime: `${process.hrtime(startTime)[1] / 1000000}ms`
      });
    }

    // Final comparison
    if (decryptedText === account.authData.expectedText) {
      return res.json({ 
        success: true, 
        message: "Access granted",
        processingTime: `${process.hrtime(startTime)[1] / 1000000}ms`
      });
    }

    return res.status(403).json({ 
      success: false, 
      message: "Access denied: Invalid NFC data",
      processingTime: `${process.hrtime(startTime)[1] / 1000000}ms`
    });

  } catch (err) {
    console.error('Auth error:', err);
    return res.status(500).json({ 
      success: false, 
      message: "Internal server error",
      processingTime: `${process.hrtime(startTime)[1] / 1000000}ms`
    });
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
