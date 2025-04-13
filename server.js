const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const path = require("path");
const os = require("os");
const crypto = require("crypto");

const app = express();

// MongoDB connection URI
const mongoURI = "mongodb+srv://zzayir21:rifah5657@cluster21.7c8bhzd.mongodb.net/loginDB?retryWrites=true&w=majority";

// AES-256-CBC decryption function
function decrypt(encryptedBase64, key, iv) {
  const decipher = crypto.createDecipheriv(
    "aes-256-cbc",
    Buffer.from(key, "utf-8"),
    Buffer.from(iv, "utf-8")
  );
  let decrypted = decipher.update(encryptedBase64, "base64", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

// Connect to MongoDB
mongoose.connect(mongoURI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
  .then(() => console.log("✅ Connected to MongoDB Atlas"))
  .catch(err => console.error("❌ MongoDB connection error:", err));

// User Schema
const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  aesKey: String,
  expectedText: String,
  allowedSerial: String
});

const User = mongoose.model("User", userSchema);

// Manager Schema (in 'employee' collection)
const managerSchema = new mongoose.Schema({
  username: String,
  password: String,
  aesKey: String,
  expectedText: String,
  allowedSerial: String
});

const Manager = mongoose.model("Manager", managerSchema, "employee");

app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, "public")));

// ===== LOGIN ROUTES =====

// Login endpoint (User)
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ username, password });

    if (!user) {
      return res.json({ message: "Invalid credentials" });
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
    console.error("User login error:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// Login endpoint (Manager)
app.post("/manager-login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const manager = await Manager.findOne({ username, password });

    if (!manager) {
      return res.json({ message: "Invalid credentials" });
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
    console.error("Manager login error:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// ===== NFC AUTHENTICATION ROUTE =====
app.post("/api/nfc-auth", async (req, res) => {
  const { encryptedData, serial, username, isManager } = req.body;

  try {
    const Model = isManager ? Manager : User;
    const account = await Model.findOne({ username });

    if (!account) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    const iv = "0000000000000000"; // 16-byte static IV (or retrieve from DB if you stored it)
    const decryptedText = decrypt(encryptedData, account.aesKey, iv);

    if (decryptedText === account.expectedText && serial === account.allowedSerial) {
      return res.json({ success: true, message: "Access granted" });
    } else {
      return res.json({ success: false, message: "Access denied" });
    }

  } catch (err) {
    console.error("NFC auth error:", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

// ====== HELPER: Get Local IP ======
function getLocalIP() {
  const interfaces = os.networkInterfaces();
  for (let name in interfaces) {
    for (let iface of interfaces[name]) {
      if (iface.family === "IPv4" && !iface.internal) {
        return iface.address;
      }
    }
  }
  return "localhost";
}



// ====== START SERVER ======
const PORT = process.env.PORT || 3010;
app.listen(PORT, "0.0.0.0", () => {
  const localIP = getLocalIP();
  console.log(`\n✅ Server running at:`);
  console.log(`👉 PC:     http://localhost:${PORT}`);
  console.log(`👉 Mobile: http://${localIP}:${PORT}\n`);
});
