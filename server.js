const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const path = require("path");

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


// User schema
const User = mongoose.model("User", {
  username: String,
  password: String,
});

app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, "public")));

// Login endpoint
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = await User.findOne({ username, password });

  if (user) {
    res.json({ message: "Login successful" });
    
  } else {
    res.json({ message: "Invalid credentials" });
  }
});

// MANAGER LOGIN ENDPOINT
// Manager Schema
const managerSchema = new mongoose.Schema({
  username: String,
  password: String,
});

const Manager = mongoose.model("Manager", managerSchema, "employee");



// Route: Manager Login
app.post("/manager-login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const manager = await Manager.findOne({ username, password });

    if (!manager) {
      return res.json({ message: "Invalid username or password" });
    }

    res.json({ message: "Login successful" });

  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Server error" });
  }
});




const os = require("os");

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

app.listen(PORT, "0.0.0.0", () => {
  const localIP = getLocalIP();
  console.log(`\n✅ Server running at:`);
  console.log(`👉 PC:     http://localhost:${PORT}`);
  console.log(`👉 Mobile: http://${localIP}:${PORT}\n`);
});


