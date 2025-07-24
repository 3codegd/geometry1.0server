const express = require("express");
const fs = require("fs");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");

const app = express();
app.use(express.json());

const USERS_FILE = "users.json";
const SECRET_KEY = "your-very-secure-secret-key"; // Replace this with env variable in production

/* --------- Helper functions --------- */
function loadJson(path, fallback = []) {
  try {
    return JSON.parse(fs.readFileSync(path, "utf8"));
  } catch {
    return fallback;
  }
}

function saveJson(path, data) {
  fs.writeFileSync(path, JSON.stringify(data, null, 2));
}

/* --------- Authentication Middleware --------- */
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "Missing Authorization header" });

  const token = authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Missing token" });

  try {
    const payload = jwt.verify(token, SECRET_KEY);
    req.user = payload; // payload contains { id, username, isAdmin }
    next();
  } catch {
    res.status(401).json({ error: "Invalid or expired token" });
  }
}

function adminOnly(req, res, next) {
  if (req.user?.isAdmin) return next();
  res.status(403).json({ error: "Admin access required" });
}

/* --------- User Registration --------- */
app.post("/register", async (req, res) => {
  const { username, password, isAdmin } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: "Username and password required" });
  }

  let users = loadJson(USERS_FILE);
  if (users.find(u => u.username === username)) {
    return res.status(400).json({ error: "Username already taken" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = {
    id: uuidv4(),
    username,
    password: hashedPassword,
    isAdmin: isAdmin === true // Only set if explicitly true, default false
  };
  users.push(newUser);
  saveJson(USERS_FILE, users);

  res.json({ success: true, message: "User registered" });
});

/* --------- User Login --------- */
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const users = loadJson(USERS_FILE);

  const user = users.find(u => u.username === username);
  if (!user) {
    return res.status(401).json({ error: "Invalid username or password" });
  }

  const passwordMatch = await bcrypt.compare(password, user.password);
  if (!passwordMatch) {
    return res.status(401).json({ error: "Invalid username or password" });
  }

  // Create JWT token
  const token = jwt.sign(
    { id: user.id, username: user.username, isAdmin: user.isAdmin },
    SECRET_KEY,
    { expiresIn: "1h" }
  );

  res.json({ success: true, token });
});

/* --------- Example Protected Route --------- */
app.get("/profile", authMiddleware, (req, res) => {
  res.json({
    message: `Welcome, ${req.user.username}!`,
    isAdmin: req.user.isAdmin
  });
});

/* --------- Admin-only Route Example --------- */
app.get("/admin/dashboard", authMiddleware, adminOnly, (req, res) => {
  res.json({ message: "Welcome to the admin dashboard." });
});

/* --------- Add your other routes here --------- */

/* --------- Custom 404 --------- */
app.use((req, res) => {
  res.status(404).json({
    error: `000: cannot ${req.method} ${req.originalUrl}`
  });
});

/* --------- Start Server --------- */
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
});

