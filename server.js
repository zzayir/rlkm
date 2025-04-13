const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const path = require("path");
const os = require("os");

const app = express();

// MongoDB connection URI - Consider using environment variables for sensitive data
const mongoURI = "mongodb+srv://zzayir21:rifah5657@cluster21.7c8bhzd.mongodb.net/loginDB?retryWrites=true&w=majority";



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
const crypto = require("crypto");

function decrypt(encryptedData, aesKey, iv) {
  const decipher = crypto.createDecipheriv("aes-256-cbc", Buffer.from(aesKey), Buffer.from(iv));
  let decrypted = decipher.update(encryptedData, "base64", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

app.post("/api/nfc-auth", async (req, res, next) => {
  try {
    const { encryptedData, serial, username, isManager } = req.body;
    
    // Input validation
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

    const iv = "0000000000000000"; // Static IV for simplicity, use a random IV in production
    const decryptedText = decrypt(encryptedData, account.aesKey, iv);

    if (!decryptedText) {
      return res.status(400).json({ 
        success: false, 
        message: "Decryption failed" 
      });
    }

    // Check if the decrypted text matches the expected text and serial number
    if (decryptedText === account.expectedText && serial === account.allowedSerial) {
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
