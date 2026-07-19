import express from 'express';
import cookieParser from 'cookie-parser';
import Stripe from 'stripe';
import fs from 'fs';
import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pg from 'pg';
import 'dotenv/config';

const { Pool } = pg;

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

// ── Database (Postgres) ─────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && !process.env.DATABASE_URL.includes('localhost')
    ? { rejectUnauthorized: false }
    : undefined,
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL, name TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'both',
      stripe_account_id TEXT, charges_enabled INTEGER NOT NULL DEFAULT 0,
      rides_completed INTEGER NOT NULL DEFAULT 0,
      rating_sum INTEGER NOT NULL DEFAULT 0, rating_count INTEGER NOT NULL DEFAULT 0,
      subscription_tier TEXT, subscription_status TEXT NOT NULL DEFAULT 'none',
      created_at TEXT NOT NULL
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS rides (
      id TEXT PRIMARY KEY, driver_id TEXT NOT NULL REFERENCES users(id),
      from_loc TEXT NOT NULL, to_loc TEXT NOT NULL, ride_date TEXT,
      seats_total INTEGER NOT NULL, seats_available INTEGER NOT NULL,
      contribution_type TEXT NOT NULL, price_cents INTEGER,
      status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS route_requests (
      id TEXT PRIMARY KEY, hitcher_id TEXT NOT NULL REFERENCES users(id),
      from_loc TEXT NOT NULL, to_loc TEXT NOT NULL, request_date TEXT,
      contribution_pref TEXT, note TEXT, status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT NOT NULL
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS bookings (
      id TEXT PRIMARY KEY, ride_id TEXT NOT NULL REFERENCES rides(id),
      hitcher_id TEXT NOT NULL REFERENCES users(id),
      status TEXT NOT NULL DEFAULT 'pending',
      price_cents INTEGER, stripe_session_id TEXT, created_at TEXT NOT NULL
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS ratings (
      id TEXT PRIMARY KEY, booking_id TEXT NOT NULL REFERENCES bookings(id),
      rater_id TEXT NOT NULL REFERENCES users(id),
      ratee_id TEXT NOT NULL REFERENCES users(id),
      stars INTEGER NOT NULL, punctuality INTEGER, company INTEGER,
      condition INTEGER, safety INTEGER, comment TEXT, created_at TEXT NOT NULL,
      UNIQUE(booking_id, rater_id)
    );
  `);
}

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
app.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  let event;
  try {
    event = stripe.webhooks.constructEvent(
      req.body, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) { return res.status(400).send(`Webhook Error: ${err.message}`); }

  try {
    if (event.type === 'checkout.session.completed') {
      const { kind, bookingId, userId, priceKey } = event.data.object.metadata || {};
      if (kind === 'ride_booking' && bookingId) {
        const { rows } = await pool.query('SELECT * FROM bookings WHERE id = $1', [bookingId]);
        const booking = rows[0];
        if (booking?.status === 'pending') {
          await pool.query(`UPDATE bookings SET status = 'paid' WHERE id = $1`, [bookingId]);
          await pool.query('UPDATE rides SET seats_available = seats_available - 1 WHERE id = $1', [booking.ride_id]);
        }
      }
      if (kind === 'subscription' && userId) {
        await pool.query(
          `UPDATE users SET subscription_tier = $1, subscription_status = 'active' WHERE id = $2`,
          [priceKey, userId]
        );
      }
    }
    if (event.type === 'account.updated') {
      const a = event.data.object;
      await pool.query('UPDATE users SET charges_enabled = $1 WHERE stripe_account_id = $2',
        [a.charges_enabled ? 1 : 0, a.id]);
    }
    res.json({ received: true });
  } catch (err) {
    console.error('Webhook handler error:', err);
    res.status(500).json({ error: 'Webhook handler failed.' });
  }
});

app.use(cookieParser());
app.use(express.json());
app.use(attachUser);
app.use(express.static('public'));

// ── Auth ───────────────────────────────────────────────────────────────────
app.post('/auth/signup', async (req, res) => {
  try {
    const { email, password, name, role } = req.body;
    if (!email || !password || !name)
      return res.status(400).json({ error: 'Name, email and password are required.' });
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email.toLowerCase().trim()]);
    if (existing.rows[0])
      return res.status(409).json({ error: 'An account with that email already exists.' });
    const id = crypto.randomUUID();
    await pool.query(
      `INSERT INTO users (id,email,password_hash,name,role,created_at) VALUES ($1,$2,$3,$4,$5,$6)`,
      [id, email.toLowerCase().trim(), bcrypt.hashSync(password, 10), name.trim(), role||'both', now()]
    );
    setAuthCookie(res, id);
    const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    res.json({ user: publicProfile(rows[0]) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/auth/login', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [(req.body.email||'').toLowerCase().trim()]);
    const user = rows[0];
    if (!user || !bcrypt.compareSync(req.body.password||'', user.password_hash))
      return res.status(401).json({ error: 'Email or password is incorrect.' });
    setAuthCookie(res, user.id);
    res.json({ user: publicProfile(user) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/auth/logout', (req, res) => { res.clearCookie(COOKIE); res.json({ ok: true }); });

app.get('/auth/me', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [req.userId]);
    if (!rows[0]) return res.status(404).json({ error: 'Account not found.' });
    res.json({ user: publicProfile(rows[0]) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── Rides ──────────────────────────────────────────────────────────────────
app.post('/drivers/connect-account', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [req.userId]);
    const user = rows[0];
    let accountId = user.stripe_account_id;
    if (!accountId) {
      const account = await stripe.accounts.create({
        type: 'express', email: user.email,
        capabilities: { card_payments: { requested: true }, transfers: { requested: true } },
      });
      accountId = account.id;
      await pool.query('UPDATE users SET stripe_account_id = $1 WHERE id = $2', [accountId, req.userId]);
    }
    const link = await stripe.accountLinks.create({
      account: accountId, type: 'account_onboarding',
      refresh_url: `${APP_URL}/?onboarding=refresh`,
      return_url: `${APP_URL}/?onboarding=complete`,
    });
    res.json({ url: link.url });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/rides', requireAuth, async (req, res) => {
  try {
    const { from, to, date, seats, contributionType, priceCents } = req.body;
    if (!from||!to||!seats||!contributionType)
      return res.status(400).json({ error: 'From, to, seats and contribution type are required.' });
    if (contributionType === 'price') {
      const { rows } = await pool.query('SELECT charges_enabled FROM users WHERE id = $1', [req.userId]);
      const driver = rows[0];
      if (!driver.charges_enabled)
        return res.status(400).json({ error: 'Connect with Stripe before listing a priced ride.' });
      if (!priceCents || priceCents < 1)
        return res.status(400).json({ error: 'Set a price greater than zero.' });
    }
    const id = crypto.randomUUID();
    await pool.query(
      `INSERT INTO rides (id,driver_id,from_loc,to_loc,ride_date,seats_total,seats_available,contribution_type,price_cents,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [id, req.userId, from.trim(), to.trim(), date||null, seats, seats, contributionType, priceCents||null, now()]
    );
    const { rows } = await pool.query('SELECT * FROM rides WHERE id = $1', [id]);
    res.json({ ride: rows[0] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/route-requests', requireAuth, async (req, res) => {
  try {
    const { from, to, date, contributionPref, note } = req.body;
    if (!from||!to) return res.status(400).json({ error: 'From and to are required.' });
    const id = crypto.randomUUID();
    await pool.query(
      `INSERT INTO route_requests (id,hitcher_id,from_loc,to_loc,request_date,contribution_pref,note,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [id, req.userId, from.trim(), to.trim(), date||null, contributionPref||null, note||null, now()]
    );
    const { rows } = await pool.query('SELECT * FROM route_requests WHERE id = $1', [id]);
    res.json({ request: rows[0] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/route-requests', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT rr.*,u.name AS hitcher_name FROM route_requests rr JOIN users u ON u.id=rr.hitcher_id WHERE rr.status='active' ORDER BY rr.created_at DESC LIMIT 50`
    );
    res.json({ requests: rows });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/rides', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT r.*,u.name AS driver_name,u.rating_sum,u.rating_count FROM rides r JOIN users u ON u.id=r.driver_id WHERE r.status='active' AND r.seats_available>0 ORDER BY r.created_at DESC LIMIT 50`
    );
    res.json({ rides: rows.map(r => ({
      id: r.id, from: r.from_loc, to: r.to_loc, date: r.ride_date,
      seatsAvailable: r.seats_available, contributionType: r.contribution_type,
      priceCents: r.price_cents, driverName: r.driver_name,
      driverRating: r.rating_count ? Math.round((r.rating_sum/r.rating_count)*10)/10 : null,
    })) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/rides/:id/book', requireAuth, async (req, res) => {
  try {
    const { rows: rideRows } = await pool.query('SELECT * FROM rides WHERE id = $1', [req.params.id]);
    const ride = rideRows[0];
    if (!ride||ride.status!=='active') return res.status(404).json({ error: 'Ride not available.' });
    if (ride.seats_available < 1) return res.status(400).json({ error: 'No seats left.' });
    if (ride.driver_id === req.userId) return res.status(400).json({ error: "You can't book your own ride." });
    const bookingId = crypto.randomUUID();
    if (ride.contribution_type !== 'price') {
      await pool.query(
        `INSERT INTO bookings (id,ride_id,hitcher_id,status,created_at) VALUES ($1,$2,$3,'confirmed',$4)`,
        [bookingId, ride.id, req.userId, now()]
      );
      await pool.query('UPDATE rides SET seats_available=seats_available-1 WHERE id=$1', [ride.id]);
      return res.json({ booking: { id: bookingId, status: 'confirmed' } });
    }
    const { rows: driverRows } = await pool.query('SELECT stripe_account_id FROM users WHERE id=$1', [ride.driver_id]);
    const driver = driverRows[0];
    await pool.query(
      `INSERT INTO bookings (id,ride_id,hitcher_id,status,price_cents,created_at) VALUES ($1,$2,$3,'pending',$4,$5)`,
      [bookingId, ride.id, req.userId, ride.price_cents, now()]
    );
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
    await pool.query('UPDATE bookings SET stripe_session_id=$1 WHERE id=$2', [session.id, bookingId]);
    res.json({ url: session.url });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/bookings/:id/complete', requireAuth, async (req, res) => {
  try {
    const { rows: bookingRows } = await pool.query('SELECT * FROM bookings WHERE id=$1', [req.params.id]);
    const booking = bookingRows[0];
    if (!booking) return res.status(404).json({ error: 'Booking not found.' });
    const { rows: rideRows } = await pool.query('SELECT * FROM rides WHERE id=$1', [booking.ride_id]);
    const ride = rideRows[0];
    if (ride.driver_id !== req.userId) return res.status(403).json({ error: 'Only the driver can do this.' });
    await pool.query(`UPDATE bookings SET status='completed' WHERE id=$1`, [booking.id]);
    await pool.query('UPDATE users SET rides_completed=rides_completed+1 WHERE id IN ($1,$2)', [ride.driver_id, booking.hitcher_id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/bookings/:id/rate', requireAuth, async (req, res) => {
  try {
    const { stars, comment } = req.body;
    if (!stars||stars<1||stars>5) return res.status(400).json({ error: 'Stars must be 1-5.' });
    const { rows: bookingRows } = await pool.query('SELECT * FROM bookings WHERE id=$1', [req.params.id]);
    const booking = bookingRows[0];
    if (!booking||booking.status!=='completed') return res.status(400).json({ error: 'Can only rate completed rides.' });
    const { rows: rideRows } = await pool.query('SELECT driver_id FROM rides WHERE id=$1', [booking.ride_id]);
    const ride = rideRows[0];
    const rateeId = req.userId===ride.driver_id ? booking.hitcher_id :
                    req.userId===booking.hitcher_id ? ride.driver_id : null;
    if (!rateeId) return res.status(403).json({ error: "You weren't part of this ride." });
    try {
      await pool.query(
        `INSERT INTO ratings (id,booking_id,rater_id,ratee_id,stars,comment,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
        [crypto.randomUUID(), booking.id, req.userId, rateeId, stars, comment||null, now()]
      );
      await pool.query('UPDATE users SET rating_sum=rating_sum+$1,rating_count=rating_count+1 WHERE id=$2', [stars, rateeId]);
      res.json({ ok: true });
    } catch (err) {
      if (err.code === '23505') return res.status(409).json({ error: 'Already rated.' });
      throw err;
    }
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/me/activity', requireAuth, async (req, res) => {
  try {
    const ridesOffered = await pool.query(
      `SELECT r.*,(SELECT COUNT(*) FROM bookings b WHERE b.ride_id=r.id AND b.status!='cancelled') AS booking_count FROM rides r WHERE r.driver_id=$1 ORDER BY r.created_at DESC`,
      [req.userId]
    );
    const bookingsAsDriver = await pool.query(
      `SELECT b.*,r.from_loc,r.to_loc,u.name AS hitcher_name FROM bookings b JOIN rides r ON r.id=b.ride_id JOIN users u ON u.id=b.hitcher_id WHERE r.driver_id=$1 ORDER BY b.created_at DESC`,
      [req.userId]
    );
    const bookingsAsHitcher = await pool.query(
      `SELECT b.*,r.from_loc,r.to_loc,u.name AS driver_name FROM bookings b JOIN rides r ON r.id=b.ride_id JOIN users u ON u.id=r.driver_id WHERE b.hitcher_id=$1 ORDER BY b.created_at DESC`,
      [req.userId]
    );
    res.json({
      ridesOffered: ridesOffered.rows,
      bookingsAsDriver: bookingsAsDriver.rows,
      bookingsAsHitcher: bookingsAsHitcher.rows,
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── Subscriptions & add-ons ────────────────────────────────────────────────
app.post('/subscribe', requireAuth, async (req, res) => {
  try {
    const prices = loadPrices();
    const priceId = prices[req.body.priceKey];
    if (!priceId) return res.status(400).json({ error: 'Run "npm run setup" first.' });
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription', customer_email: req.body.customerEmail,
      line_items: [{ price: priceId, quantity: 1 }],
      metadata: { kind: 'subscription', priceKey: req.body.priceKey, userId: req.userId },
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
initDb()
  .then(() => {
    app.listen(port, () => console.log(`ridem8 running on :${port}`));
  })
  .catch(err => {
    console.error('Failed to initialize database:', err);
    process.exit(1);
  });
