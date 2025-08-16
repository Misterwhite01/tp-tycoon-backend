import express from "express";
import cors from "cors";
import helmet from "helmet";
import dotenv from "dotenv";
import mongoose from "mongoose";
import jwt from "jsonwebtoken";
import bodyParser from "body-parser";
import rateLimit from "express-rate-limit";
import Stripe from "stripe";

dotenv.config();

const app = express();
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || "");

// Raw body for webhooks
app.use((req, res, next) => {
  if (req.originalUrl === "/webhook") {
    bodyParser.raw({ type: "application/json" })(req, res, next);
  } else {
    bodyParser.json()(req, res, next);
  }
});

app.use(cors());
app.use(helmet());

// --- Rate limiting ---
const apiLimiter = rateLimit({
  windowMs: (parseInt(process.env.RATE_LIMIT_WINDOW_MIN || "1") * 60 * 1000),
  max: parseInt(process.env.RATE_LIMIT_MAX || "120"),
});
app.use("/api", apiLimiter);

// --- DB ---
const MONGO_URI = process.env.MONGO_URI;
if (!MONGO_URI) {
  console.error("Missing MONGO_URI");
  process.exit(1);
}
await mongoose.connect(MONGO_URI);

// --- Schemas ---
const UserSchema = new mongoose.Schema({
  email: { type: String, unique: true, index: true },
  createdAt: { type: Date, default: Date.now },
  lastLoginAt: { type: Date, default: Date.now },
  authCode: { type: String },
  authCodeExpiresAt: { type: Date },
  coins: { type: Number, default: 0 },
  totalDistance: { type: Number, default: 0 },
  prestigeLevel: { type: Number, default: 0 },
  prestigeMultiplier: { type: Number, default: 1 },
  lastRollAt: { type: Date },
  daily: {
    dayCount: { type: Number, default: 0 },
    lastClaimedAt: { type: Date }
  }
});
const User = mongoose.model("User", UserSchema);

// --- Helpers ---
function signJWT(userId) {
  return jwt.sign({ uid: userId }, process.env.JWT_SECRET || "dev", { expiresIn: "60d" });
}
function auth(req, res, next) {
  const hdr = req.headers.authorization || "";
  const token = hdr.startsWith("Bearer ") ? hdr.slice(7) : null;
  if (!token) return res.status(401).json({ error: "missing token" });
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET || "dev");
    req.userId = payload.uid;
    next();
  } catch {
    return res.status(401).json({ error: "invalid token" });
  }
}

// --- Auth routes (email code printed to logs for demo) ---
app.post("/auth/request-code", async (req, res) => {
  const { email } = req.body || {};
  if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    return res.status(400).json({ error: "invalid email" });
  }
  const code = (Math.floor(100000 + Math.random()*900000)).toString();
  const expires = new Date(Date.now() + 10*60*1000);
  let user = await User.findOne({ email });
  if (!user) user = await User.create({ email });
  user.authCode = code;
  user.authCodeExpiresAt = expires;
  await user.save();
  console.log(`[AUTH CODE] For ${email}: ${code} (valid 10 min)`);
  return res.json({ ok: true, message: "Code generated. (Check server logs in demo.)" });
});

app.post("/auth/verify", async (req, res) => {
  const { email, code } = req.body || {};
  const user = await User.findOne({ email });
  if (!user || !user.authCode || !user.authCodeExpiresAt) {
    return res.status(400).json({ error: "no code requested" });
  }
  if (user.authCode !== code || user.authCodeExpiresAt < new Date()) {
    return res.status(400).json({ error: "invalid or expired code" });
  }
  user.authCode = null;
  user.authCodeExpiresAt = null;
  user.lastLoginAt = new Date();
  await user.save();
  const token = signJWT(user._id.toString());
  return res.json({ token });
});

// --- Game logic ---
function getRollResult(prestigeMultiplier = 1) {
  const base = Math.floor(Math.random() * 5) + 1; // 1..5 meters
  let coins = base;
  const jackpot = Math.random() < 0.01;
  if (jackpot) coins *= 20;
  else if (Math.random() < 0.15) coins *= 2;
  coins = Math.floor(coins * prestigeMultiplier);
  return { distance: base, coins, jackpot };
}

app.get("/api/game/state", auth, async (req, res) => {
  const user = await User.findById(req.userId).lean();
  if (!user) return res.status(404).json({ error: "not found" });
  return res.json({
    coins: user.coins,
    totalDistance: user.totalDistance,
    prestigeLevel: user.prestigeLevel,
    prestigeMultiplier: user.prestigeMultiplier,
    daily: user.daily || {},
    jackpotChance: 0.01
  });
});

app.post("/api/game/roll", auth, async (req, res) => {
  const user = await User.findById(req.userId);
  if (!user) return res.status(404).json({ error: "not found" });
  const now = Date.now();
  if (user.lastRollAt && now - user.lastRollAt.getTime() < 50) {
    return res.status(429).json({ error: "too fast" });
  }
  const result = getRollResult(user.prestigeMultiplier || 1);
  user.coins += result.coins;
  user.totalDistance += result.distance;
  user.lastRollAt = new Date(now);
  await user.save();
  return res.json({ coins: user.coins, totalDistance: user.totalDistance, jackpot: result.jackpot });
});

app.post("/api/game/prestige", auth, async (req, res) => {
  const user = await User.findById(req.userId);
  if (!user) return res.status(404).json({ error: "not found" });
  if (user.totalDistance < 1000) {
    return res.status(400).json({ error: "need 1000m to prestige" });
  }
  user.prestigeLevel += 1;
  user.prestigeMultiplier = 1 + user.prestigeLevel * 0.5;
  user.totalDistance = 0;
  await user.save();
  return res.json({ prestigeLevel: user.prestigeLevel, prestigeMultiplier: user.prestigeMultiplier });
});

app.post("/api/game/daily", auth, async (req, res) => {
  const user = await User.findById(req.userId);
  if (!user) return res.status(404).json({ error: "not found" });
  const last = user.daily?.lastClaimedAt ? new Date(user.daily.lastClaimedAt) : null;
  const now = new Date();
  const sameDay = last && last.toDateString() === now.toDateString();
  if (sameDay) return res.status(400).json({ error: "already claimed today" });
  user.daily = user.daily || { dayCount: 0 };
  let dayCount = user.daily.dayCount || 0;
  if (last) {
    const diff = (now - last) / (1000*60*60*24);
    dayCount = diff < 2 ? dayCount + 1 : 1;
  } else dayCount = 1;
  const reward = 100 * dayCount;
  user.coins += reward;
  user.daily.dayCount = dayCount;
  user.daily.lastClaimedAt = now;
  await user.save();
  return res.json({ reward, dayCount, coins: user.coins });
});

// --- Payments ---
const products = {
  gold_pack_4_99: { price: 499, name: "Gold Pack (5,000 coins)", grantCoins: 5000 },
  vip_pack_9_99: { price: 999, name: "VIP Pack (12,000 coins + x1.2 prestige boost)", grantCoins: 12000, prestigeBoost: 0.2 }
};

app.post("/api/pay/create-checkout", auth, async (req, res) => {
  try {
    const { productId } = req.body || {};
    const p = products[productId];
    if (!p) return res.status(400).json({ error: "invalid product" });
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      mode: "payment",
      line_items: [{
        price_data: {
          currency: "usd",
          product_data: { name: p.name },
          unit_amount: p.price
        },
        quantity: 1
      }],
      success_url: (process.env.APP_ORIGIN || "http://localhost:5173") + "/success?session_id={CHECKOUT_SESSION_ID}",
      cancel_url: (process.env.APP_ORIGIN || "http://localhost:5173") + "/",
      metadata: { userId: req.userId, productId }
    });
    return res.json({ checkoutUrl: session.url });
  } catch (e) {
    console.error("checkout error", e);
    return res.status(500).json({ error: "checkout failed" });
  }
});

app.post("/webhook", async (req, res) => {
  let event;
  const sig = req.headers["stripe-signature"];
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET || "");
  } catch (err) {
    console.error("Webhook signature verification failed.", err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === "checkout.session.completed") {
    const session = event.data.object;
    const userId = session.metadata?.userId;
    const productId = session.metadata?.productId;
    const p = products[productId];
    if (userId && p) {
      const user = await mongoose.model("User").findById(userId);
      if (user) {
        user.coins += p.grantCoins || 0;
        if (p.prestigeBoost) {
          user.prestigeMultiplier = (user.prestigeMultiplier || 1) * (1 + p.prestigeBoost);
        }
        await user.save();
        console.log(`Granted purchase to ${user.email}: ${p.name}`);
      }
    }
  }
  res.json({ received: true });
});

const port = process.env.PORT || 4000;
app.get("/", (req, res) => res.send("TP Tycoon backend up"));
app.listen(port, () => console.log("Backend listening on", port));
