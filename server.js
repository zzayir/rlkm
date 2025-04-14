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
function decrypt(encryptedData, aesKey, iv) {
  try {
    const decipher = crypto.createDecipheriv("aes-256-cbc", Buffer.from(aesKey, 'hex'), Buffer.from(iv, 'hex'));
    let decrypted = decipher.update(encryptedData, "base64", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
  } catch (err) {
    console.error("Decryption error:", err);
    return null;
  }
}

app.post("/api/nfc-auth", async (req, res, next) => {
  try {
    const { encryptedData, serial, username, isManager, aesKey, expectedText } = req.body;
    
    if (!encryptedData || !serial || !username) {
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

    // Use the provided key or fall back to stored key
    const decryptionKey = aesKey || account.authData.aesKey;
    const expectedDecryptedText = expectedText || account.authData.expectedText;
    
    const iv = "0000000000000000"; // Should be dynamic in production
    const decryptedText = decrypt(encryptedData, decryptionKey, iv);

    if (!decryptedText) {
      return res.status(400).json({ 
        success: false, 
        message: "Decryption failed" 
      });
    }

    // Normalize serial numbers for comparison
    const normalizeSerial = (serial) => serial ? serial.replace(/:/g, "").toUpperCase() : "";
    const normalizedInput = normalizeSerial(serial);
    const normalizedAllowed = normalizeSerial(account.authData.allowedSerial);

    if (decryptedText === expectedDecryptedText && normalizedInput === normalizedAllowed) {
      return res.json({ 
        success: true, 
        message: "Access granted" 
      });
    } else {
      return res.status(403).json({ 
        success: false, 
        message: "Access denied" 
      });
    }

  } catch (err) {
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
