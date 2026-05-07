const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const app = express();
app.use(express.json());

const users = [];

// Signup
app.post("/auth/signup", async (req, res) => {
  const { name, email, password } = req.body;

  const hashed = await bcrypt.hash(password, 10);
  const user = { id: Date.now(), name, email, password: hashed };

  users.push(user);

  const token = jwt.sign({ id: user.id }, "secret");
  res.json({ token, user });
});

// Login
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;

  const user = users.find(u => u.email === email);
  if (!user) return res.send("User not found");

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.send("Wrong password");

  const token = jwt.sign({ id: user.id }, "secret");
  res.json({ token, user });
});

// Google Login (for Flutter Firebase token)
app.post("/auth/google", (req, res) => {
  const { idToken } = req.body;

  // for now just accept token
  const user = { id: Date.now(), email: "google_user" };

  const token = jwt.sign({ id: user.id }, "secret");
  res.json({ token, user });
});

app.listen(3000, () => console.log("Server running on port 3000"));

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;

  if (!header) {
    return res.status(401).json({ message: "No token" });
  }

  const token = header.split(" ")[1];

  try {
    const decoded = require("jsonwebtoken").verify(token, "secret");
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ message: "Invalid token" });
  }
}

app.get("/api/me", authMiddleware, (req, res) => {
  res.json({
    message: "You are logged in",
    user: req.user
  });
});