const express = require("express");
const fs = require("fs");
const path = require("path");
require("dotenv").config({ path: "/etc/secrets/l328ajtWmg1" });

const app = express();
app.use(express.json());

/* ----------------------------
   Helper: JSON File Management
----------------------------- */

function loadJson(filePath, fallback = []) {
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch {
    return fallback;
  }
}

function saveJson(filePath, data) {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}

/* ----------------------------
   Data Files
----------------------------- */

const ipBansFile = "ip-bans.json";
const userBansFile = "user-bans.json";
const usersFile = "users.json";
const completionsFile = "completions.json";

let ipBans = loadJson(ipBansFile);
let userBans = loadJson(userBansFile);
let users = loadJson(usersFile);
let completions = loadJson(completionsFile);

/* ----------------------------
   Authentication Middleware
   (Mocked for demo — replace with real auth)
----------------------------- */

function mockAuth(req, res, next) {
  // Example: read username & token from headers or session
  // For demo, hardcoded admin user
  req.user = {
    username: "adminUser1",
    isAdmin: true,
  };
  next();
}

function adminOnly(req, res, next) {
  if (req.user?.isAdmin) return next();
  res.status(403).json({ error: "Admin access required" });
}

app.use(mockAuth);

/* ----------------------------
   Middleware: IP Ban Checker
----------------------------- */

function ipBanMiddleware(req, res, next) {
  const ip = req.headers["x-forwarded-for"]?.split(",")[0] || req.ip;
  const now = Date.now();

  const activeBan = ipBans.find((b) => b.ip === ip && b.expiresAt > now);
  if (activeBan) {
    return res.status(403).json({
      error: "You are temporarily banned.",
      reason: activeBan.reason,
      expiresAt: activeBan.expiresAt,
    });
  }

  next();
}

app.use(ipBanMiddleware);

/* ----------------------------
   Admin: IP Ban Routes
----------------------------- */

app.post("/admin/tempban-ip", adminOnly, (req, res) => {
  const { ip, durationMinutes, reason } = req.body;
  if (!ip || !durationMinutes) {
    return res.status(400).json({ error: "IP and duration required" });
  }

  const expiresAt = Date.now() + durationMinutes * 60 * 1000;

  ipBans.push({
    ip,
    reason: reason || "No reason provided",
    bannedBy: req.user.username,
    expiresAt,
  });

  saveJson(ipBansFile, ipBans);
  res.json({ success: true, message: `Banned ${ip} for ${durationMinutes} minutes.` });
});

app.post("/admin/unban-ip", adminOnly, (req, res) => {
  const { ip } = req.body;
  if (!ip) return res.status(400).json({ error: "IP required" });

  const before = ipBans.length;
  ipBans = ipBans.filter((b) => b.ip !== ip);
  saveJson(ipBansFile, ipBans);

  res.json({ success: true, removed: before - ipBans.length });
});

app.get("/admin/ipbans", adminOnly, (req, res) => {
  const now = Date.now();
  const active = ipBans.filter((b) => b.expiresAt > now);
  res.json(active);
});

/* ----------------------------
   Admin: Completions + Status
----------------------------- */

app.get("/admin/completions/:user", adminOnly, (req, res) => {
  const username = req.params.user;
  const userCompletions = completions.filter((c) => c.username === username);
  res.json(userCompletions);
});

app.get("/admin/banland", adminOnly, (req, res) => {
  const now = Date.now();
  const activeIpBans = ipBans.filter((b) => b.expiresAt > now);
  const activeUserBans = userBans.filter((b) => b.expiresAt > now);

  res.json({
    bannedIps: activeIpBans,
    bannedUsers: activeUserBans,
  });
});

app.get("/admin/status/:user", adminOnly, (req, res) => {
  const username = req.params.user;
  const user = users.find((u) => u.username === username);
  const now = Date.now();

  const banned = userBans.find((b) => b.username === username && b.expiresAt > now);

  res.json({
    status: banned ? "banned" : "not banned",
    isAdmin: user?.isAdmin ? "true" : "false",
  });
});

/* ----------------------------
   Test route
----------------------------- */

app.get("/", (req, res) => {
  res.send("Welcome to the server.");
});

/* ----------------------------
   Custom 404 Handler with Logging
----------------------------- */

app.use((req, res) => {
  const method = req.method;
  const fullPath = req.originalUrl;
  const ip = req.headers["x-forwarded-for"]?.split(",")[0] || req.ip;
  const timestamp = new Date().toISOString();

  const logLine = `[${timestamp}] ⚠️ 404 - ${method} ${fullPath} from IP ${ip}`;
  console.warn(logLine);

  // Optional: append to a log file
  try {
    fs.appendFileSync("access-log.txt", logLine + "\n");
  } catch (err) {
    console.error("Failed to write log:", err);
  }

  res.status(404).json({
    error: `000: cannot ${method} ${fullPath}`,
  });
});

/* ----------------------------
   Start Server
----------------------------- */

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
