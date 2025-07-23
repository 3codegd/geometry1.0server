const express = require("express");
const fs = require("fs");
const app = express();

app.use(express.json());

/* ----------------------------
   Helper: JSON File Management
----------------------------- */

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

/* ----------------------------
   Data Files (Stored Externally)
----------------------------- */

let ipBans = loadJson("ip-bans.json");
let userBans = loadJson("user-bans.json");
let users = loadJson("users.json");
let completions = loadJson("completions.json");

/* ----------------------------
   Authentication (Mocked)
----------------------------- */

function mockAuth(req, res, next) {
  req.user = {
    username: "adminUser1",
    isAdmin: true
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

  const activeBan = ipBans.find(b => b.ip === ip && b.expiresAt > now);
  if (activeBan) {
    return res.status(403).json({
      error: "You are temporarily banned.",
      reason: activeBan.reason,
      expiresAt: activeBan.expiresAt
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
    expiresAt
  });

  saveJson("ip-bans.json", ipBans);
  res.json({ success: true, message: `Banned ${ip} for ${durationMinutes} minutes.` });
});

app.post("/admin/unban-ip", adminOnly, (req, res) => {
  const { ip } = req.body;
  if (!ip) return res.status(400).json({ error: "IP required" });

  const before = ipBans.length;
  ipBans = ipBans.filter(b => b.ip !== ip);
  saveJson("ip-bans.json", ipBans);

  res.json({ success: true, removed: before - ipBans.length });
});

app.get("/admin/ipbans", adminOnly, (req, res) => {
  const now = Date.now();
  const active = ipBans.filter(b => b.expiresAt > now);
  res.json(active);
});

/* ----------------------------
   Admin: Completions + Status
----------------------------- */

app.get("/admin/completions/:user", adminOnly, (req, res) => {
  const username = req.params.user;
  const userCompletions = completions.filter(c => c.username === username);
  res.json(userCompletions);
});

app.get("/admin/banland", adminOnly, (req, res) => {
  const now = Date.now();
  const activeIpBans = ipBans.filter(b => b.expiresAt > now);
  const activeUserBans = userBans.filter(b => b.expiresAt > now);

  res.json({
    bannedIps: activeIpBans,
    bannedUsers: activeUserBans
  });
});

app.get("/admin/status/:user", adminOnly, (req, res) => {
  const username = req.params.user;
  const user = users.find(u => u.username === username);
  const now = Date.now();

  const banned = userBans.find(b => b.username === username && b.expiresAt > now);

  res.json({
    status: banned ? "banned" : "not banned",
    isAdmin: user?.isAdmin ? "true" : "false"
  });
});

/* ----------------------------
   Test Route
----------------------------- */

app.get("/", (req, res) => {
  res.send("Welcome to the server.");
});

/* ----------------------------
   Custom 404 Handler
----------------------------- */

app.use((req, res) => {
  res.status(404).json({
    error: `404: cannot ${req.method} ${req.originalUrl}`
  });
});

/* ----------------------------
   Start Server
----------------------------- */

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
});
const path = require("path"); // already built into Node.js

// Custom 404 handler with logging
app.use((req, res) => {
  const method = req.method;
  const fullPath = req.originalUrl;
  const ip = req.headers["x-forwarded-for"]?.split(",")[0] || req.ip;
  const timestamp = new Date().toISOString();

  const logLine = `[${timestamp}] ⚠️ 404 - ${method} ${fullPath} from IP ${ip}`;
  console.warn(logLine);

  // Optional: append to a log file
  fs.appendFileSync("access-log.txt", logLine + "\n");

  res.status(404).json({
    error: `000: cannot ${method} ${fullPath}`
  });
});
