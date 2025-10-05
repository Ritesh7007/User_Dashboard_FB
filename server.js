// server.js
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");

const app = express();
app.use(express.json());

// connect to MongoDB
mongoose.connect("mongodb://127.0.0.1:27017/users_dashboard")
  .then(() => console.log(" MongoDB Connected"))
  .catch(err => console.log(" MongoDB Error:", err));

// Simple hardcoded secret (OK for local testing)
const JWT_SECRET = "my_local_secret_key";
const JWT_EXPIRES_IN = "6h";


// User Schema

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  age: Number,
  password: { type: String, required: true }
}, { timestamps: true });

userSchema.methods.toJSON = function () {
  const obj = this.toObject();
  delete obj.password;
  return obj;
};

const User = mongoose.model("User", userSchema);


// JWT Helpers

function generateToken(user) {
  return jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Missing token" });
  }
  const token = header.split(" ")[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}


// Auth Routes

// Register (for testing/demo)
app.post("/auth/register", async (req, res) => {
  try {
    const { name, email, password, age } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ message: "Name, email, and password are required" });
    }
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ message: "Email already exists" });

    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, age, password: hashed });
    const token = generateToken(user);
    res.json({ user: user.toJSON(), token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// Login
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: "Invalid credentials" });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ message: "Invalid credentials" });

    const token = generateToken(user);
    res.json({ token, user: user.toJSON() });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});


// Protected CRUD

app.get("/users", authMiddleware, async (req, res) => {
  const users = await User.find().sort({ createdAt: -1 });
  res.json(users.map(u => u.toJSON()));
});

app.post("/users", authMiddleware, async (req, res) => {
  try {
    const { name, email, age, password } = req.body;
    if (!name || !email) return res.status(400).json({ message: "Name and email required" });

    const hashed = await bcrypt.hash(password || "123456", 10);
    const user = await User.create({ name, email, age, password: hashed });
    res.status(201).json(user.toJSON());
  } catch (err) {
    res.status(500).json({ message: "Error creating user" });
  }
});

app.put("/users/:id", authMiddleware, async (req, res) => {
  try {
    const { name, email, age, password } = req.body;
    const update = {};
    if (name) update.name = name;
    if (email) update.email = email;
    if (age !== undefined) update.age = age;
    if (password) update.password = await bcrypt.hash(password, 10);

    const user = await User.findByIdAndUpdate(req.params.id, update, { new: true });
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json(user.toJSON());
  } catch (err) {
    res.status(500).json({ message: "Error updating user" });
  }
});

app.delete("/users/:id", authMiddleware, async (req, res) => {
  try {
    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json({ message: "User deleted" });
  } catch (err) {
    res.status(500).json({ message: "Error deleting user" });
  }
});


// Serve Frontend

app.use(express.static(path.join(__dirname, "public")));
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public/index.html"));
});

app.listen(3000, () => console.log(" Server running at http://localhost:3000/auth.html"));
