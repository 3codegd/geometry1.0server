const express = require("express");
const fs = require("fs");
const path = require("path");
const dotenv = require("dotenv");
dotenv.config();

const app = express();
app.use(express.json());

/* ----------------------------
   Helper: JSON File Management
----------------------------- */

function loadJson(file, fallback = []) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return fallback;
  }
}

function saveJson(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

/* ----------------------------
   Data Files
----------------------------- */

let ipBans = loadJson("ip-bans.json");
let userBans = loadJson("user-bans.json");
let users = loadJson("users.json");
let completions = loadJson("completions.json");
let levels = loadJson("levels.json");

/* ----------------------------
   Middleware: IP Ban Checker
----------------------------- */

function ipBanMiddleware(req, res, next) {
  const ip = req.headers["x-forwarded-for"]?.split(",")[0] || req.ip;
  const now = Date.now();

  const ban = ipBans.find(b => b.ip === ip && b.expiresAt > now);
  if (ban) {
    return res.status(403).json({
      error: "You are temporarily banned.",
      reason: ban.reason,
      expiresAt: ban.expiresAt
    });
  }

  next();
}
app.use(ipBanMiddleware);

/* ----------------------------
   Admin Auth Middleware (Password-Based)
----------------------------- */

function adminAuth(req, res, next) {
  const auth = req.headers.authorization;
  const adminPass = process.env.ADMIN_PASSWORD;

  if (auth === `Bearer ${adminPass}`) {
    req.user = { username: "admin", isAdmin: true };
    return next();
  }

  res.status(403).json({ error: "Admin access denied" });
}

/* ----------------------------
   Public: GET /levels
----------------------------- */

app.get("/levels", (req, res) => {
  res.json(levels);
});

/* ----------------------------
   Admin: IP Ban Routes
----------------------------- */

app.post("/admin/tempban-ip", adminAuth, (req, res) => {
  const { ip, durationMinutes, reason } = req.body;
  if (!ip || !durationMinutes) {
    return res.status(400).json({ error: "IP and duration required" });
  }

  const expiresAt = Date.now() + durationMinutes * 60 * 1000;
  ipBans.push({
    ip,
    reason: reason || "No reason provided",
    bannedBy: req.user.username,
    expiresAt
  });

  saveJson("ip-bans.json", ipBans);
  res.json({ success: true });
});

app.post("/admin/unban-ip", adminAuth, (req, res) => {
  const { ip } = req.body;
  if (!ip) return res.status(400).json({ error: "IP required" });

  const before = ipBans.length;
  ipBans = ipBans.filter(b => b.ip !== ip);
  saveJson("ip-bans.json", ipBans);
  res.json({ success: true, removed: before - ipBans.length });
});

app.get("/admin/ipbans", adminAuth, (req, res) => {
  const now = Date.now();
  res.json(ipBans.filter(b => b.expiresAt > now));
});

/* ----------------------------
   Admin: Completion + Status
----------------------------- */

app.get("/admin/completions/:user", adminAuth, (req, res) => {
  const name = req.params.user;
  res.json(completions.filter(c => c.username === name));
});

app.get("/admin/banland", adminAuth, (req, res) => {
  const now = Date.now();
  res.json({
    bannedIps: ipBans.filter(b => b.expiresAt > now),
    bannedUsers: userBans.filter(b => b.expiresAt > now)
  });
});

app.get("/admin/status/:user", adminAuth, (req, res) => {
  const name = req.params.user;
  const now = Date.now();
  const banned = userBans.find(b => b.username === name && b.expiresAt > now);
  const user = users.find(u => u.username === name);
  res.json({
    status: banned ? "banned" : "not banned",
    isAdmin: user?.isAdmin ? "true" : "false"
  });
});

/* ----------------------------
   Root Route
----------------------------- */

app.get("/", (req, res) => {
  res.send("Welcome to the server.");
});

/* ----------------------------
   Custom 404 Handler
----------------------------- */

app.use((req, res) => {
  const ip = req.headers["x-forwarded-for"]?.split(",")[0] || req.ip;
  const line = `[${new Date().toISOString()}] 404 - ${req.method} ${req.originalUrl} from ${ip}`;
  console.warn(line);
  fs.appendFileSync("access-log.txt", line + "\n");

  res.status(404).json({
    error: `000: cannot ${req.method} ${req.originalUrl}`
  });
});

/* ----------------------------
   Start Server
----------------------------- */

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
});
