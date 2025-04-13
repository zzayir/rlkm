const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const path = require("path");
const os = require("os");

const app = express();
const PORT = 3010;

// MongoDB connection
const mongoURI = "mongodb+srv://zzayir21:rifah5657@cluster21.7c8bhzd.mongodb.net/loginDB?retryWrites=true&w=majority";

mongoose.connect(mongoURI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log("✅ Connected to MongoDB Atlas"))
.catch((err) => console.error("❌ MongoDB connection error:", err));

// User Schema
const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  aesKey: String,
  expectedText: String,
  allowedSerial: String
});

const User = mongoose.model("User", userSchema);

// Manager Schema (same structure)
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
      return res.json({ message: "Invalid username or password" });
    }

    res.json({
      message: "Login successful",
      aesKey: manager.aesKey,
      expectedText: manager.expectedText,
      allowedSerial: manager.allowedSerial
    });

  } catch (error) {
    console.error("Manager login error:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// Get local IP
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

// Start server
app.listen(PORT, "0.0.0.0", () => {
  const localIP = getLocalIP();
  console.log(`\n✅ Server running at:`);
  console.log(`👉 PC:     http://localhost:${PORT}`);
  console.log(`👉 Mobile: http://${localIP}:${PORT}\n`);
});
