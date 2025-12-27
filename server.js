// Simple Express + SQLite + Socket.io chat server (minimal, for MVP)
const express = require("express");
const http = require("http");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const { Server } = require("socket.io");
const rateLimit = require("express-rate-limit");
const path = require("path");

const JWT_SECRET = process.env.JWT_SECRET || "change-this-secret";
const PORT = process.env.PORT || 3000;

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*", methods: ["GET", "POST"] }
});

app.use(express.json());
app.use(cookieParser());

// Basic rate limiter for signup/login endpoints
const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { error: "Too many requests, try again later." }
});
app.use("/signup", authLimiter);
app.use("/login", authLimiter);

// Init SQLite (file db for simplicity)
const db = new sqlite3.Database("./chat.db");
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    email TEXT UNIQUE,
    password_hash TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS rooms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    room_id INTEGER,
    user_id INTEGER,
    username TEXT,
    content TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  // create a default room
  db.run(`INSERT OR IGNORE INTO rooms (id, name) VALUES (1, 'general')`);
});

// Helpers
function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "12h" });
}
function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (e) {
    return null;
  }
}

// Signup
app.post("/signup", async (req, res) => {
  const { username, email, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: "username and password required" });
  const hash = await bcrypt.hash(password, 10);
  db.run(
    `INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)`,
    [username, email || null, hash],
    function (err) {
      if (err) {
        return res.status(400).json({ error: "username or email already taken" });
      }
      const user = { id: this.lastID, username };
      const token = signToken(user);
      // set token in httpOnly cookie
      res.cookie("token", token, { httpOnly: true, sameSite: "lax" });
      res.json({ success: true, user });
    }
  );
});

// Login
app.post("/login", (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: "username and password required" });
  db.get(`SELECT id, username, password_hash FROM users WHERE username = ?`, [username], async (err, row) => {
    if (err || !row) return res.status(401).json({ error: "invalid credentials" });
    const ok = await bcrypt.compare(password, row.password_hash);
    if (!ok) return res.status(401).json({ error: "invalid credentials" });
    const user = { id: row.id, username: row.username };
    const token = signToken(user);
    res.cookie("token", token, { httpOnly: true, sameSite: "lax" });
    res.json({ success: true, user });
  });
});

// Logout
app.post("/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ success: true });
});

// Get current user (from cookie)
app.get("/me", (req, res) => {
  const token = req.cookies.token;
  const payload = verifyToken(token);
  if (!payload) return res.json({ user: null });
  res.json({ user: payload });
});

// List rooms
app.get("/rooms", (req, res) => {
  db.all(`SELECT id, name FROM rooms ORDER BY id`, [], (err, rows) => {
    res.json({ rooms: rows || [] });
  });
});

// Get last 50 messages for a room
app.get("/rooms/:id/messages", (req, res) => {
  const roomId = Number(req.params.id || 1);
  db.all(
    `SELECT id, username, content, created_at FROM messages WHERE room_id = ? ORDER BY id DESC LIMIT 50`,
    [roomId],
    (err, rows) => {
      res.json({ messages: (rows || []).reverse() });
    }
  );
});

// Simple profanity filter (very small example)
const banned = ["badword1", "badword2"];
function sanitizeMessage(text) {
  let out = text;
  banned.forEach((w) => {
    const r = new RegExp(w, "ig");
    out = out.replace(r, "****");
  });
  // limit length
  if (out.length > 1000) out = out.slice(0, 1000);
  return out;
}

// Socket.io auth + chat
io.use((socket, next) => {
  const token = socket.handshake.auth?.token || (socket.handshake.headers?.cookie || "").split("token=")[1];
  const payload = verifyToken(token);
  if (!payload) return next(new Error("unauthorized"));
  socket.data.user = payload;
  return next();
});

// per-socket cooldown in ms
const MESSAGE_COOLDOWN = 800;
io.on("connection", (socket) => {
  const user = socket.data.user;
  socket.data.lastMessageAt = 0;
  console.log(`user connected: ${user.username}`);

  socket.on("join", (roomId = 1, cb) => {
    roomId = Number(roomId || 1);
    socket.join(`room_${roomId}`);
    cb && cb({ ok: true });
  });

  socket.on("leave", (roomId = 1, cb) => {
    roomId = Number(roomId || 1);
    socket.leave(`room_${roomId}`);
    cb && cb({ ok: true });
  });

  socket.on("message", (payload, cb) => {
    try {
      const now = Date.now();
      if (now - socket.data.lastMessageAt < MESSAGE_COOLDOWN) {
        return cb && cb({ error: "You are sending messages too fast." });
      }
      socket.data.lastMessageAt = now;
      const { roomId = 1, content = "" } = payload || {};
      const clean = sanitizeMessage(String(content || ""));
      // persist message
      db.run(
        `INSERT INTO messages (room_id, user_id, username, content) VALUES (?, ?, ?, ?)`,
        [roomId, user.id, user.username, clean],
        function (err) {
          const msg = {
            id: this.lastID,
            username: user.username,
            content: clean,
            created_at: new Date().toISOString()
          };
          io.to(`room_${roomId}`).emit("message", msg);
          cb && cb({ ok: true });
        }
      );
    } catch (e) {
      cb && cb({ error: "server error" });
    }
  });

  socket.on("disconnect", () => {
    console.log(`user disconnected: ${user.username}`);
  });
});

// serve client static single page for convenience
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "client.html")));

server.listen(PORT, () => console.log(`Server listening on ${PORT}`));
