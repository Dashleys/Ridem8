import express from 'express';
import cookieParser from 'cookie-parser';
import Stripe from 'stripe';
import fs from 'fs';
import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import Database from 'better-sqlite3';
import 'dotenv/config';

// ── Auto-generate JWT secret on first run ──────────────────────────────────
if (!process.env.JWT_SECRET) {
  const secret = crypto.randomBytes(32).toString('hex');
  let env = fs.existsSync('.env') ? fs.readFileSync('.env', 'utf8') : '';
  env += `\nJWT_SECRET=${secret}\n`;
  fs.writeFileSync('.env', env);
  process.env.JWT_SECRET = secret;
}

const JWT_SECRET = process.env.JWT_SECRET;
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const APP_URL = process.env.APP_URL;

// ── Database ───────────────────────────────────────────────────────────────
const db = new Database('./ridem8.db');
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL, name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'both',
    stripe_account_id TEXT, charges_enabled INTEGER NOT NULL DEFAULT 0,
    rides_completed INTEGER NOT NULL DEFAULT 0,
    rating_sum INTEGER NOT NULL DEFAULT 0, rating_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS rides (
    id TEXT PRIMARY KEY, driver_id TEXT NOT NULL REFERENCES users(id),
    from_loc TEXT NOT NULL, to_loc TEXT NOT NULL, ride_date TEXT,
    seats_total INTEGER NOT NULL, seats_available INTEGER NOT NULL,
    contribution_type TEXT NOT NULL, price_cents INTEGER,
    status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS route_requests (
    id TEXT PRIMARY KEY, hitcher_id TEXT NOT NULL REFERENCES users(id),
    from_loc TEXT NOT NULL, to_loc TEXT NOT NULL, request_date TEXT,
    contribution_pref TEXT, note TEXT, status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS bookings (
    id TEXT PRIMARY KEY, ride_id TEXT NOT NULL REFERENCES rides(id),
    hitcher_id TEXT NOT NULL REFERENCES users(id),
    status TEXT NOT NULL DEFAULT 'pending',
    price_cents INTEGER, stripe_session_id TEXT, created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS ratings (
    id TEXT PRIMARY KEY, booking_id TEXT NOT NULL REFERENCES bookings(id),
    rater_id TEXT NOT NULL REFERENCES users(id),
    ratee_id TEXT NOT NULL REFERENCES users(id),
    stars INTEGER NOT NULL, punctuality INTEGER, company INTEGER,
    condition INTEGER, safety INTEGER, comment TEXT, created_at TEXT NOT NULL,
    UNIQUE(booking_id, rater_id)
  );
`);

// ── Auth helpers ───────────────────────────────────────────────────────────
const COOKIE = 'ridem8_token';
const COOKIE_OPTS = { httpOnly: true, sameSite: 'lax', maxAge: 30*24*60*60*1000 };

function setAuthCookie(res, userId) {
  res.cookie(COOKIE, jwt.sign({ uid: userId }, JWT_SECRET, { expiresIn: '30d' }), COOKIE_OPTS);
}
function attachUser(req, res, next) {
  const token = req.cookies?.[COOKIE];
  if (token) { try { req.userId = jwt.verify(token, JWT_SECRET).uid; } catch {} }
  next();
}
function requireAuth(req, res, next) {
  if (!req.userId) return res.status(401).json({ error: 'Please log in first.' });
  next();
}
function publicProfile(u) {
  return {
    id: u.id, name: u.name, email: u.email, role: u.role,
    chargesEnabled: !!u.charges_enabled, stripeAccountId: u.stripe_account_id,
    ridesCompleted: u.rides_completed,
    ratingAvg: u.rating_count ? Math.round((u.rating_sum/u.rating_count)*10)/10 : null,
    ratingCount: u.rating_count,
  };
}
function loadPrices() {
  try { return JSON.parse(fs.readFileSync('./price-ids.json','utf8')); } catch { return {}; }
}
const now = () => new Date().toISOString();

// ── Express ────────────────────────────────────────────────────────────────
const app = express();

// Webhook must be before express.json()
app.post('/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  let event;
  try {
    event = stripe.webhooks.constructEvent(
      req.body, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) { return res.status(400).send(`Webhook Error: ${err.message}`); }

  if (event.type === 'checkout.session.completed') {
    const { kind, bookingId } = event.data.object.metadata || {};
    if (kind === 'ride_booking' && bookingId) {
      const booking = db.prepare('SELECT * FROM bookings WHERE id = ?').get(bookingId);
      if (booking?.status === 'pending') {
        db.prepare(`UPDATE bookings SET status = 'paid' WHERE id = ?`).run(bookingId);
        db.prepare('UPDATE rides SET seats_available = seats_available - 1 WHERE id = ?').run(booking.ride_id);
      }
    }
  }
  if (event.type === 'account.updated') {
    const a = event.data.object;
    db.prepare('UPDATE users SET charges_enabled = ? WHERE stripe_account_id = ?')
      .run(a.charges_enabled ? 1 : 0, a.id);
  }
  res.json({ received: true });
});

app.use(cookieParser());
app.use(express.json());
app.use(attachUser);
app.use(express.static('public'));

// ── Auth ───────────────────────────────────────────────────────────────────
app.post('/auth/signup', (req, res) => {
  const { email, password, name, role } = req.body;
  if (!email || !password || !name)
    return res.status(400).json({ error: 'Name, email and password are required.' });
  if (db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase().trim()))
    return res.status(409).json({ error: 'An account with that email already exists.' });
  const id = crypto.randomUUID();
  db.prepare(`INSERT INTO users (id,email,password_hash,name,role,created_at) VALUES (?,?,?,?,?,?)`)
    .run(id, email.toLowerCase().trim(), bcrypt.hashSync(password, 10), name.trim(), role||'both', now());
  setAuthCookie(res, id);
  res.json({ user: publicProfile(db.prepare('SELECT * FROM users WHERE id = ?').get(id)) });
});

app.post('/auth/login', (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get((req.body.email||'').toLowerCase().trim());
  if (!user || !bcrypt.compareSync(req.body.password||'', user.password_hash))
    return res.status(401).json({ error: 'Email or password is incorrect.' });
  setAuthCookie(res, user.id);
  res.json({ user: publicProfile(user) });
});

app.post('/auth/logout', (req, res) => { res.clearCookie(COOKIE); res.json({ ok: true }); });

app.get('/auth/me', requireAuth, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.userId);
  if (!user) return res.status(404).json({ error: 'Account not found.' });
  res.json({ user: publicProfile(user) });
});

// ── Rides ──────────────────────────────────────────────────────────────────
app.post('/drivers/connect-account', requireAuth, async (req, res) => {
  try {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.userId);
    let accountId = user.stripe_account_id;
    if (!accountId) {
      const account = await stripe.accounts.create({
        type: 'express', email: user.email,
        capabilities: { card_payments: { requested: true }, transfers: { requested: true } },
      });
      accountId = account.id;
      db.prepare('UPDATE users SET stripe_account_id = ? WHERE id = ?').run(accountId, req.userId);
    }
    const link = await stripe.accountLinks.create({
      account: accountId, type: 'account_onboarding',
      refresh_url: `${APP_URL}/?onboarding=refresh`,
      return_url: `${APP_URL}/?onboarding=complete`,
    });
    res.json({ url: link.url });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/rides', requireAuth, (req, res) => {
  const { from, to, date, seats, contributionType, priceCents } = req.body;
  if (!from||!to||!seats||!contributionType)
    return res.status(400).json({ error: 'From, to, seats and contribution type are required.' });
  if (contributionType === 'price') {
    const driver = db.prepare('SELECT charges_enabled FROM users WHERE id = ?').get(req.userId);
    if (!driver.charges_enabled)
      return res.status(400).json({ error: 'Connect with Stripe before listing a priced ride.' });
    if (!priceCents || priceCents < 1)
      return res.status(400).json({ error: 'Set a price greater than zero.' });
  }
  const id = crypto.randomUUID();
  db.prepare(`INSERT INTO rides (id,driver_id,from_loc,to_loc,ride_date,seats_total,seats_available,contribution_type,price_cents,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)`)
    .run(id, req.userId, from.trim(), to.trim(), date||null, seats, seats, contributionType, priceCents||null, now());
  res.json({ ride: db.prepare('SELECT * FROM rides WHERE id = ?').get(id) });
});

app.post('/route-requests', requireAuth, (req, res) => {
  const { from, to, date, contributionPref, note } = req.body;
  if (!from||!to) return res.status(400).json({ error: 'From and to are required.' });
  const id = crypto.randomUUID();
  db.prepare(`INSERT INTO route_requests (id,hitcher_id,from_loc,to_loc,request_date,contribution_pref,note,created_at) VALUES (?,?,?,?,?,?,?,?)`)
    .run(id, req.userId, from.trim(), to.trim(), date||null, contributionPref||null, note||null, now());
  res.json({ request: db.prepare('SELECT * FROM route_requests WHERE id = ?').get(id) });
});

app.get('/route-requests', (req, res) => {
  res.json({ requests: db.prepare(
    `SELECT rr.*,u.name AS hitcher_name FROM route_requests rr JOIN users u ON u.id=rr.hitcher_id WHERE rr.status='active' ORDER BY rr.created_at DESC LIMIT 50`
  ).all() });
});

app.get('/rides', (req, res) => {
  const rows = db.prepare(
    `SELECT r.*,u.name AS driver_name,u.rating_sum,u.rating_count FROM rides r JOIN users u ON u.id=r.driver_id WHERE r.status='active' AND r.seats_available>0 ORDER BY r.created_at DESC LIMIT 50`
  ).all();
  res.json({ rides: rows.map(r => ({
    id: r.id, from: r.from_loc, to: r.to_loc, date: r.ride_date,
    seatsAvailable: r.seats_available, contributionType: r.contribution_type,
    priceCents: r.price_cents, driverName: r.driver_name,
    driverRating: r.rating_count ? Math.round((r.rating_sum/r.rating_count)*10)/10 : null,
  })) });
});

app.post('/rides/:id/book', requireAuth, async (req, res) => {
  try {
    const ride = db.prepare('SELECT * FROM rides WHERE id = ?').get(req.params.id);
    if (!ride||ride.status!=='active') return res.status(404).json({ error: 'Ride not available.' });
    if (ride.seats_available < 1) return res.status(400).json({ error: 'No seats left.' });
    if (ride.driver_id === req.userId) return res.status(400).json({ error: "You can't book your own ride." });
    const bookingId = crypto.randomUUID();
    if (ride.contribution_type !== 'price') {
      db.prepare(`INSERT INTO bookings (id,ride_id,hitcher_id,status,created_at) VALUES (?,?,?,'confirmed',?)`)
        .run(bookingId, ride.id, req.userId, now());
      db.prepare('UPDATE rides SET seats_available=seats_available-1 WHERE id=?').run(ride.id);
      return res.json({ booking: { id: bookingId, status: 'confirmed' } });
    }
    const driver = db.prepare('SELECT stripe_account_id FROM users WHERE id=?').get(ride.driver_id);
    db.prepare(`INSERT INTO bookings (id,ride_id,hitcher_id,status,price_cents,created_at) VALUES (?,?,?,'pending',?,?)`)
      .run(bookingId, ride.id, req.userId, ride.price_cents, now());
    const fee = Math.min(Math.round(ride.price_cents * 0.05), 300);
    const session = await stripe.checkout.sessions.create({
      mode: 'payment',
      line_items: [{ price_data: { currency: 'nzd', unit_amount: ride.price_cents,
        product_data: { name: `${ride.from_loc} → ${ride.to_loc}` } }, quantity: 1 }],
      payment_intent_data: { application_fee_amount: fee,
        transfer_data: { destination: driver.stripe_account_id } },
      metadata: { kind: 'ride_booking', bookingId },
      success_url: `${APP_URL}/?booked=1`, cancel_url: `${APP_URL}/?booked=0`,
    });
    db.prepare('UPDATE bookings SET stripe_session_id=? WHERE id=?').run(session.id, bookingId);
    res.json({ url: session.url });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/bookings/:id/complete', requireAuth, (req, res) => {
  const booking = db.prepare('SELECT * FROM bookings WHERE id=?').get(req.params.id);
  if (!booking) return res.status(404).json({ error: 'Booking not found.' });
  const ride = db.prepare('SELECT * FROM rides WHERE id=?').get(booking.ride_id);
  if (ride.driver_id !== req.userId) return res.status(403).json({ error: 'Only the driver can do this.' });
  db.prepare(`UPDATE bookings SET status='completed' WHERE id=?`).run(booking.id);
  db.prepare('UPDATE users SET rides_completed=rides_completed+1 WHERE id IN (?,?)').run(ride.driver_id, booking.hitcher_id);
  res.json({ ok: true });
});

app.post('/bookings/:id/rate', requireAuth, (req, res) => {
  const { stars, comment } = req.body;
  if (!stars||stars<1||stars>5) return res.status(400).json({ error: 'Stars must be 1-5.' });
  const booking = db.prepare('SELECT * FROM bookings WHERE id=?').get(req.params.id);
  if (!booking||booking.status!=='completed') return res.status(400).json({ error: 'Can only rate completed rides.' });
  const ride = db.prepare('SELECT driver_id FROM rides WHERE id=?').get(booking.ride_id);
  const rateeId = req.userId===ride.driver_id ? booking.hitcher_id :
                  req.userId===booking.hitcher_id ? ride.driver_id : null;
  if (!rateeId) return res.status(403).json({ error: "You weren't part of this ride." });
  try {
    db.prepare(`INSERT INTO ratings (id,booking_id,rater_id,ratee_id,stars,comment,created_at) VALUES (?,?,?,?,?,?,?)`)
      .run(crypto.randomUUID(), booking.id, req.userId, rateeId, stars, comment||null, now());
    db.prepare('UPDATE users SET rating_sum=rating_sum+?,rating_count=rating_count+1 WHERE id=?').run(stars, rateeId);
    res.json({ ok: true });
  } catch (err) {
    if (String(err).includes('UNIQUE')) return res.status(409).json({ error: 'Already rated.' });
    res.status(500).json({ error: err.message });
  }
});

app.get('/me/activity', requireAuth, (req, res) => {
  res.json({
    ridesOffered: db.prepare(`SELECT r.*,(SELECT COUNT(*) FROM bookings b WHERE b.ride_id=r.id AND b.status!='cancelled') AS booking_count FROM rides r WHERE r.driver_id=? ORDER BY r.created_at DESC`).all(req.userId),
    bookingsAsDriver: db.prepare(`SELECT b.*,r.from_loc,r.to_loc,u.name AS hitcher_name FROM bookings b JOIN rides r ON r.id=b.ride_id JOIN users u ON u.id=b.hitcher_id WHERE r.driver_id=? ORDER BY b.created_at DESC`).all(req.userId),
    bookingsAsHitcher: db.prepare(`SELECT b.*,r.from_loc,r.to_loc,u.name AS driver_name FROM bookings b JOIN rides r ON r.id=b.ride_id JOIN users u ON u.id=r.driver_id WHERE b.hitcher_id=? ORDER BY b.created_at DESC`).all(req.userId),
  });
});

// ── Subscriptions & add-ons ────────────────────────────────────────────────
app.post('/subscribe', async (req, res) => {
  try {
    const prices = loadPrices();
    const priceId = prices[req.body.priceKey];
    if (!priceId) return res.status(400).json({ error: 'Run "npm run setup" first.' });
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription', customer_email: req.body.customerEmail,
      line_items: [{ price: priceId, quantity: 1 }],
      metadata: { kind: 'subscription', priceKey: req.body.priceKey },
      success_url: `${APP_URL}/?subscribed=1`, cancel_url: `${APP_URL}/?cancelled=1`,
    });
    res.json({ url: session.url });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/addons/checkout', async (req, res) => {
  try {
    const prices = loadPrices();
    const priceId = prices[req.body.priceKey];
    if (!priceId) return res.status(400).json({ error: 'Run "npm run setup" first.' });
    const session = await stripe.checkout.sessions.create({
      mode: 'payment', line_items: [{ price: priceId, quantity: 1 }],
      metadata: { kind: 'addon', priceKey: req.body.priceKey },
      success_url: `${APP_URL}/?addon=success`, cancel_url: `${APP_URL}/?cancelled=1`,
    });
    res.json({ url: session.url });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/prices', (req, res) => {
  const prices = loadPrices();
  res.json({ ready: Object.keys(prices).length > 0, keys: Object.keys(prices) });
});

const port = process.env.PORT || 4000;
app.listen(port, () => console.log(`ridem8 running on :${port}`));
