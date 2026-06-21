const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const cookieParser = require("cookie-parser");

const app = express();
app.use(express.json());
app.use(cookieParser());

const SALT_ROUNDS = 12;
const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET || crypto.randomBytes(64).toString("hex");
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || crypto.randomBytes(64).toString("hex");
const ACCESS_TTL = "15m";
const REFRESH_TTL = "7d";

const users = new Map();
const refreshTokens = new Set();

function generateAccessToken(user) {
  return jwt.sign({ id: user.id, email: user.email, role: user.role }, ACCESS_SECRET, { expiresIn: ACCESS_TTL });
}

function generateRefreshToken(user) {
  const token = jwt.sign({ id: user.id, tid: crypto.randomUUID() }, REFRESH_SECRET, { expiresIn: REFRESH_TTL });
  refreshTokens.add(token);
  return token;
}

function cookieOpts(maxAge) {
  return { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "strict", path: "/", maxAge };
}

// REGISTER
app.post("/register", async (req, res) => {
  try {
    const { email, password, role } = req.body;
    if (!email || !password) return res.status(400).json({ error: "email and password required" });
    if (users.has(email)) return res.status(409).json({ error: "user already exists" });
    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    const user = { id: crypto.randomUUID(), email, password: hash, role: role || "user" };
    users.set(email, user);
    res.status(201).json({ id: user.id, email: user.email, role: user.role });
  } catch (e) {
    res.status(500).json({ error: "registration failed" });
  }
});

// LOGIN
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "email and password required" });
    const user = users.get(email);
    if (!user) return res.status(401).json({ error: "invalid credentials" });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: "invalid credentials" });
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    res.cookie("accessToken", accessToken, cookieOpts(15 * 60 * 1000));
    res.cookie("refreshToken", refreshToken, cookieOpts(7 * 24 * 60 * 60 * 1000));
    res.json({ message: "login successful", user: { id: user.id, email: user.email, role: user.role } });
  } catch (e) {
    res.status(500).json({ error: "login failed" });
  }
});

// REFRESH
app.post("/refresh", (req, res) => {
  const token = req.cookies.refreshToken || req.body.refreshToken;
  if (!token || !refreshTokens.has(token)) return res.status(401).json({ error: "invalid refresh token" });
  try {
    const decoded = jwt.verify(token, REFRESH_SECRET);
    const user = [...users.values()].find((u) => u.id === decoded.id);
    if (!user) return res.status(401).json({ error: "user not found" });
    refreshTokens.delete(token);
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    res.cookie("accessToken", accessToken, cookieOpts(15 * 60 * 1000));
    res.cookie("refreshToken", refreshToken, cookieOpts(7 * 24 * 60 * 60 * 1000));
    res.json({ message: "tokens refreshed" });
  } catch (e) {
    refreshTokens.delete(token);
    res.status(401).json({ error: "refresh token expired" });
  }
});

// LOGOUT
app.post("/logout", (req, res) => {
  const token = req.cookies.refreshToken;
  if (token) refreshTokens.delete(token);
  res.clearCookie("accessToken", cookieOpts(0));
  res.clearCookie("refreshToken", cookieOpts(0));
  res.json({ message: "logout successful" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Auth API running on port ${PORT}`));

module.exports = app;