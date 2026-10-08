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

// ── Cost-sharing compliance ─────────────────────────────────────────────────
// NZTA-gazetted per-km reimbursement cap for cost-sharing arrangements.
// Update this via env var the moment TSL confirms a rate — no code change needed.
const MAX_REIMBURSEMENT_PER_KM_CENTS = parseInt(process.env.MAX_REIMBURSEMENT_PER_KM_CENTS || '73', 10);

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
      boost_credits INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS rides (
      id TEXT PRIMARY KEY, driver_id TEXT NOT NULL REFERENCES users(id),
      from_loc TEXT NOT NULL, to_loc TEXT NOT NULL, ride_date TEXT,
      seats_total INTEGER NOT NULL, seats_available INTEGER NOT NULL,
      contribution_type TEXT NOT NULL, price_cents INTEGER, petrol_note TEXT, boosted_until TEXT,
      status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL
    );
  `);
  // price_cents on rides is the driver's reimbursement claim only (cost-share, capped by law).
  // The facilitator fee is calculated and shown separately at booking time — never folded into price_cents.
  await pool.query(`ALTER TABLE rides ADD COLUMN IF NOT EXISTS distance_km NUMERIC;`);
  await pool.query(`ALTER TABLE rides ADD COLUMN IF NOT EXISTS departure_time TEXT;`);
  await pool.query(`ALTER TABLE bookings ADD COLUMN IF NOT EXISTS facilitator_fee_cents INTEGER;`);
  await pool.query(`ALTER TABLE bookings ADD COLUMN IF NOT EXISTS reimbursement_cents INTEGER;`);
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
  // ── Recurring routes ("regulars") ──────────────────────────────────────────
  // A driver posts a standing route (e.g. Wanaka→Cromwell, Tue/Thu, 8am) once.
  // generateRecurringRideInstances() then creates the actual bookable `rides`
  // rows ahead of time, and auto-seats anyone the driver has already approved.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS recurring_routes (
      id TEXT PRIMARY KEY, driver_id TEXT NOT NULL REFERENCES users(id),
      from_loc TEXT NOT NULL, to_loc TEXT NOT NULL,
      days_of_week INTEGER[] NOT NULL, departure_time TEXT NOT NULL,
      seats_total INTEGER NOT NULL, contribution_type TEXT NOT NULL,
      price_cents INTEGER, distance_km NUMERIC, petrol_note TEXT,
      active BOOLEAN NOT NULL DEFAULT true, created_at TEXT NOT NULL
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS recurring_route_subscribers (
      id TEXT PRIMARY KEY, route_id TEXT NOT NULL REFERENCES recurring_routes(id),
      hitcher_id TEXT NOT NULL REFERENCES users(id),
      status TEXT NOT NULL DEFAULT 'pending', created_at TEXT NOT NULL,
      UNIQUE(route_id, hitcher_id)
    );
  `);
  await pool.query(`ALTER TABLE rides ADD COLUMN IF NOT EXISTS recurring_route_id TEXT REFERENCES recurring_routes(id);`);
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS idx_rides_recurring_unique
    ON rides (recurring_route_id, ride_date) WHERE recurring_route_id IS NOT NULL;
  `);
  // ── Notifications (join requests, approvals, bookings) ──────────────────
  await pool.query(`
    CREATE TABLE IF NOT EXISTS notifications (
      id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
      type TEXT NOT NULL, message TEXT NOT NULL,
      read BOOLEAN NOT NULL DEFAULT false, created_at TEXT NOT NULL
    );
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications (user_id, created_at DESC);`);
}

async function notify(userId, type, message) {
  await pool.query(
    `INSERT INTO notifications (id,user_id,type,message,created_at) VALUES ($1,$2,$3,$4,$5)`,
    [crypto.randomUUID(), userId, type, message, now()]
  );
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
    subscriptionTier: u.subscription_tier,
    subscriptionStatus: u.subscription_status,
    boostCredits: u.boost_credits,
  };
}
function loadPrices() {
  try { return JSON.parse(fs.readFileSync('./price-ids.json','utf8')); } catch { return {}; }
}
const now = () => new Date().toISOString();

const BLOCKED_TERMS = [
  'fuck', 'shit', 'bitch', 'asshole', 'cunt', 'bastard', 'dick', 'pussy',
  'cock', 'whore', 'slut', 'nigger', 'faggot', 'retard',
  'hookup', 'hook up', 'dtf', 'nudes', 'sext', 'sexting',
  'want to fuck', 'wanna fuck', 'looking for sex', 'nsa fun', 'fwb',
];
function containsBlockedContent(text) {
  if (!text) return false;
  const lower = text.toLowerCase();
  return BLOCKED_TERMS.some(term => lower.includes(term));
}

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
      const { kind, bookingId, userId, priceKey, rideId, duration } = event.data.object.metadata || {};
      if (kind === 'ride_booking' && bookingId) {
        const { rows } = await pool.query('SELECT * FROM bookings WHERE id = $1', [bookingId]);
        const booking = rows[0];
        if (booking?.status === 'pending') {
          await pool.query(`UPDATE bookings SET status = 'paid' WHERE id = $1`, [bookingId]);
          await pool.query('UPDATE rides SET seats_available = seats_available - 1 WHERE id = $1', [booking.ride_id]);
          const { rows: rideRows } = await pool.query('SELECT driver_id, from_loc, to_loc FROM rides WHERE id=$1', [booking.ride_id]);
          const { rows: hitcherRows } = await pool.query('SELECT name FROM users WHERE id=$1', [booking.hitcher_id]);
          if (rideRows[0]) {
            await notify(rideRows[0].driver_id, 'booking', `${hitcherRows[0]?.name || 'Someone'} paid for a seat on your ${rideRows[0].from_loc} → ${rideRows[0].to_loc} ride.`);
          }
          // s30Q trip record. Failure is logged so the booking still completes.
          try {
            const { rows: rr } = await pool.query('SELECT * FROM rides WHERE id=$1', [booking.ride_id]);
            const { rows: br } = await pool.query('SELECT * FROM bookings WHERE id=$1', [bookingId]);
            const ride = rr[0];
            const bk = br[0];
            const session = event.data.object;
            const piId = session.payment_intent;
            let transferId = null;
            if (piId) {
              const pi = await stripe.paymentIntents.retrieve(piId, { expand: ['latest_charge'] });
              transferId = (pi.latest_charge && pi.latest_charge.transfer) || null;
            }
            let tripDate = new Date(ride.ride_date);
            if (isNaN(tripDate.getTime())) tripDate = new Date();
            const rate = Number(process.env.RATE_CENTS_PER_KM || 73);
            await pool.query(
              'INSERT INTO trip_records (ride_id, booking_id, driver_id, passenger_id, trip_date, origin, destination, distance_km, seats, rate_cents_per_km, driver_payout_cents, facilitator_fee_cents, passenger_paid_cents, stripe_payment_intent_id, stripe_transfer_id, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,1,$9,$10,$11,$12,$13,$14,NOW()) ON CONFLICT (stripe_payment_intent_id) DO NOTHING',
              [ride.id, bk.id, ride.driver_id, bk.hitcher_id, tripDate, ride.from_loc, ride.to_loc, ride.distance_km, rate, bk.reimbursement_cents, bk.facilitator_fee_cents, session.amount_total, piId, transferId]
            );
          } catch (e) { console.error('trip_records insert failed:', e.message); }
        }
      }
      if (kind === 'subscription' && userId) {
        await pool.query(
          `UPDATE users SET subscription_tier = $1, subscription_status = 'active' WHERE id = $2`,
          [priceKey, userId]
        );
        if (priceKey === 'roadTripperAnnual') {
          await pool.query('UPDATE users SET boost_credits = boost_credits + 2 WHERE id = $1', [userId]);
        }
      }
      if (kind === 'addon' && (priceKey === 'boost' || priceKey === 'boostWeek') && rideId) {
        const ms = duration === '7d' ? 7*24*60*60*1000 : 24*60*60*1000;
        const boostedUntil = new Date(Date.now() + ms).toISOString();
        await pool.query('UPDATE rides SET boosted_until = $1 WHERE id = $2', [boostedUntil, rideId]);
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
    const { from, to, date, departureTime, seats, contributionType, priceCents, petrolNote, distanceKm } = req.body;
    if (!from||!to||!seats||!contributionType)
      return res.status(400).json({ error: 'From, to, seats and contribution type are required.' });
    if (date && date < new Date().toISOString().split('T')[0])
      return res.status(400).json({ error: 'Please choose a date from today onwards.' });
    if (containsBlockedContent(petrolNote)) return res.status(400).json({ error: 'Please remove inappropriate language from your note.' });
    if (contributionType === 'price') {
      const { rows } = await pool.query('SELECT charges_enabled FROM users WHERE id = $1', [req.userId]);
      const driver = rows[0];
      if (!driver.charges_enabled)
        return res.status(400).json({ error: 'Connect with Stripe before listing a priced ride.' });
      if (!priceCents || priceCents < 1)
        return res.status(400).json({ error: 'Set a price greater than zero.' });
      // Reimbursement (what the driver claims for fuel/vehicle cost) must stay under the
      // gazetted per-km cap so the ride qualifies as cost-sharing rather than a commercial fare.
      if (distanceKm && priceCents > Math.round(distanceKm * MAX_REIMBURSEMENT_PER_KM_CENTS)) {
        return res.status(400).json({
          error: `Reimbursement can't exceed $${(MAX_REIMBURSEMENT_PER_KM_CENTS/100).toFixed(2)}/km. For ${distanceKm}km, the max is $${(Math.round(distanceKm * MAX_REIMBURSEMENT_PER_KM_CENTS)/100).toFixed(2)}.`
        });
      }
    }
    const id = crypto.randomUUID();
    await pool.query(
      `INSERT INTO rides (id,driver_id,from_loc,to_loc,ride_date,seats_total,seats_available,contribution_type,price_cents,petrol_note,created_at,distance_km,departure_time) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
      [id, req.userId, from.trim(), to.trim(), date||null, seats, seats, contributionType, priceCents||null, petrolNote||null, now(), distanceKm||null, departureTime||null]
    );
    const { rows } = await pool.query('SELECT * FROM rides WHERE id = $1', [id]);
    res.json({ ride: rows[0] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/route-requests', requireAuth, async (req, res) => {
  try {
    const { from, to, date, contributionPref, note } = req.body;
    if (!from||!to) return res.status(400).json({ error: 'From and to are required.' });
    if (date && date < new Date().toISOString().split('T')[0])
      return res.status(400).json({ error: 'Please choose a date from today onwards.' });
    if (containsBlockedContent(note)) return res.status(400).json({ error: 'Please remove inappropriate language from your note.' });
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
      `SELECT r.*,u.name AS driver_name,u.rating_sum,u.rating_count FROM rides r JOIN users u ON u.id=r.driver_id WHERE r.status='active' AND r.seats_available>0 ORDER BY (r.boosted_until IS NOT NULL AND r.boosted_until::timestamptz > NOW()) DESC, r.created_at DESC LIMIT 50`
    );
    let bookedRideIds = new Set();
    if (req.userId) {
      const { rows: myBookings } = await pool.query(
        "SELECT ride_id FROM bookings WHERE hitcher_id = $1 AND status != 'cancelled'",
        [req.userId]
      );
      bookedRideIds = new Set(myBookings.map(b => b.ride_id));
    }
    res.json({ rides: rows.map(r => ({
      id: r.id, from: r.from_loc, to: r.to_loc, date: r.ride_date,
      seatsAvailable: r.seats_available, contributionType: r.contribution_type,
      priceCents: r.price_cents, distanceKm: r.distance_km, petrolNote: r.petrol_note, departureTime: r.departure_time, isBoosted: !!(r.boosted_until && new Date(r.boosted_until) > new Date()), isRegular: !!r.recurring_route_id, driverName: r.driver_name, driverId: r.driver_id,
      driverRating: r.rating_count ? Math.round((r.rating_sum/r.rating_count)*10)/10 : null,
      alreadyBooked: bookedRideIds.has(r.id),
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
    const { rows: existingRows } = await pool.query(
      `SELECT id FROM bookings WHERE ride_id = $1 AND hitcher_id = $2 AND status != 'cancelled'`,
      [ride.id, req.userId]
    );
    if (existingRows.length > 0) return res.status(400).json({ error: "You've already booked a seat on this ride." });
    const bookingId = crypto.randomUUID();
    if (ride.contribution_type !== 'price') {
      await pool.query(
        `INSERT INTO bookings (id,ride_id,hitcher_id,status,created_at) VALUES ($1,$2,$3,'confirmed',$4)`,
        [bookingId, ride.id, req.userId, now()]
      );
      await pool.query('UPDATE rides SET seats_available=seats_available-1 WHERE id=$1', [ride.id]);
      const { rows: hitcherRows } = await pool.query('SELECT name FROM users WHERE id=$1', [req.userId]);
      await notify(ride.driver_id, 'booking', `${hitcherRows[0]?.name || 'Someone'} booked a seat on your ${ride.from_loc} → ${ride.to_loc} ride.`);
      return res.json({ booking: { id: bookingId, status: 'confirmed' } });
    }
    const { rows: driverRows } = await pool.query('SELECT stripe_account_id, rides_completed, subscription_status, subscription_tier FROM users WHERE id=$1', [ride.driver_id]);
    const driver = driverRows[0];
    await pool.query(
      `INSERT INTO bookings (id,ride_id,hitcher_id,status,price_cents,created_at) VALUES ($1,$2,$3,'pending',$4,$5)`,
      [bookingId, ride.id, req.userId, ride.price_cents, now()]
    );
    const subActive = driver.subscription_status === 'active';
    let feeRate = 0.10;
    if (subActive && driver.subscription_tier === 'roadTripperAnnual') feeRate = 0.04;
    else if (subActive && driver.subscription_tier === 'driverPlusMonthly') feeRate = 0.06;
    else if (driver.rides_completed >= 20) feeRate = 0.08;
    // ride.price_cents is the driver's cost-share reimbursement only. The facilitator
    // fee is charged ON TOP as its own line item — never deducted from the driver's
    // reimbursement — so the driver receives ride.price_cents in full via Stripe Connect.
    const reimbursementCents = ride.price_cents;
    const fee = Math.round(reimbursementCents * feeRate);
    await pool.query('UPDATE bookings SET reimbursement_cents=$1, facilitator_fee_cents=$2 WHERE id=$3', [reimbursementCents, fee, bookingId]);
    const session = await stripe.checkout.sessions.create({
      mode: 'payment',
      line_items: [
        { price_data: { currency: 'nzd', unit_amount: reimbursementCents,
          product_data: { name: `Cost-share reimbursement: ${ride.from_loc} → ${ride.to_loc}` } }, quantity: 1 },
        { price_data: { currency: 'nzd', unit_amount: fee,
          product_data: { name: 'ridem8 booking fee' } }, quantity: 1 },
      ],
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

// Shared with /rides/:id/book and /bookings/:id/pay (used by recurring-route
// auto-seating, where the booking row already exists before payment happens).
async function createReimbursementCheckoutSession(booking, ride, driver) {
  const subActive = driver.subscription_status === 'active';
  let feeRate = 0.10;
  if (subActive && driver.subscription_tier === 'roadTripperAnnual') feeRate = 0.04;
  else if (subActive && driver.subscription_tier === 'driverPlusMonthly') feeRate = 0.06;
  else if (driver.rides_completed >= 20) feeRate = 0.08;
  const reimbursementCents = ride.price_cents;
  const fee = Math.round(reimbursementCents * feeRate);
  await pool.query('UPDATE bookings SET reimbursement_cents=$1, facilitator_fee_cents=$2 WHERE id=$3', [reimbursementCents, fee, booking.id]);
  const session = await stripe.checkout.sessions.create({
    mode: 'payment',
    line_items: [
      { price_data: { currency: 'nzd', unit_amount: reimbursementCents,
        product_data: { name: `Cost-share reimbursement: ${ride.from_loc} → ${ride.to_loc}` } }, quantity: 1 },
      { price_data: { currency: 'nzd', unit_amount: fee,
        product_data: { name: 'ridem8 booking fee' } }, quantity: 1 },
    ],
    payment_intent_data: { application_fee_amount: fee,
      transfer_data: { destination: driver.stripe_account_id } },
    metadata: { kind: 'ride_booking', bookingId: booking.id },
    success_url: `${APP_URL}/?booked=1`, cancel_url: `${APP_URL}/?booked=0`,
  });
  await pool.query('UPDATE bookings SET stripe_session_id=$1 WHERE id=$2', [session.id, booking.id]);
  return session;
}

// Completes payment on a booking that already exists in 'pending' status —
// this is how a hitcher pays for a seat that was auto-reserved on a regular
// route (see generateRecurringRideInstances). Priced one-off bookings still
// go through /rides/:id/book, which creates+pays in a single step.
app.post('/bookings/:id/pay', requireAuth, async (req, res) => {
  try {
    const { rows: bookingRows } = await pool.query('SELECT * FROM bookings WHERE id=$1 AND hitcher_id=$2', [req.params.id, req.userId]);
    const booking = bookingRows[0];
    if (!booking) return res.status(404).json({ error: 'Booking not found.' });
    if (booking.status !== 'pending') return res.status(400).json({ error: 'This booking is not awaiting payment.' });
    const { rows: rideRows } = await pool.query('SELECT * FROM rides WHERE id=$1', [booking.ride_id]);
    const ride = rideRows[0];
    const { rows: driverRows } = await pool.query('SELECT stripe_account_id, rides_completed, subscription_status, subscription_tier FROM users WHERE id=$1', [ride.driver_id]);
    const driver = driverRows[0];
    const session = await createReimbursementCheckoutSession(booking, ride, driver);
    res.json({ url: session.url });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── Recurring routes ("regulars") ────────────────────────────────────────────
function validDaysOfWeek(arr) {
  return Array.isArray(arr) && arr.length > 0 && arr.every(d => Number.isInteger(d) && d >= 0 && d <= 6);
}

app.post('/recurring-routes', requireAuth, async (req, res) => {
  try {
    const { from, to, daysOfWeek, departureTime, seats, contributionType, priceCents, petrolNote, distanceKm } = req.body;
    if (!from||!to||!seats||!contributionType||!departureTime)
      return res.status(400).json({ error: 'From, to, seats, departure time and contribution type are required.' });
    if (!validDaysOfWeek(daysOfWeek))
      return res.status(400).json({ error: 'Pick at least one valid day of the week.' });
    if (containsBlockedContent(petrolNote)) return res.status(400).json({ error: 'Please remove inappropriate language from your note.' });
    if (contributionType === 'price') {
      const { rows } = await pool.query('SELECT charges_enabled FROM users WHERE id = $1', [req.userId]);
      if (!rows[0]?.charges_enabled)
        return res.status(400).json({ error: 'Connect with Stripe before listing a priced route.' });
      if (!priceCents || priceCents < 1)
        return res.status(400).json({ error: 'Set a price greater than zero.' });
      if (distanceKm && priceCents > Math.round(distanceKm * MAX_REIMBURSEMENT_PER_KM_CENTS)) {
        return res.status(400).json({
          error: `Reimbursement can't exceed $${(MAX_REIMBURSEMENT_PER_KM_CENTS/100).toFixed(2)}/km. For ${distanceKm}km, the max is $${(Math.round(distanceKm * MAX_REIMBURSEMENT_PER_KM_CENTS)/100).toFixed(2)}.`
        });
      }
    }
    const id = crypto.randomUUID();
    await pool.query(
      `INSERT INTO recurring_routes (id,driver_id,from_loc,to_loc,days_of_week,departure_time,seats_total,contribution_type,price_cents,distance_km,petrol_note,created_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
      [id, req.userId, from.trim(), to.trim(), daysOfWeek, departureTime, seats, contributionType, priceCents||null, distanceKm||null, petrolNote||null, now()]
    );
    const { rows } = await pool.query('SELECT * FROM recurring_routes WHERE id=$1', [id]);
    await generateRecurringRideInstances(); // create the next occurrences immediately, not on the next hourly tick
    res.json({ route: rows[0] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/recurring-routes', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT rr.*, u.name AS driver_name, u.rating_sum, u.rating_count
       FROM recurring_routes rr JOIN users u ON u.id=rr.driver_id
       WHERE rr.active=true ORDER BY rr.created_at DESC LIMIT 50`
    );
    res.json({ routes: rows });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/recurring-routes/mine', requireAuth, async (req, res) => {
  try {
    const { rows: routes } = await pool.query(
      `SELECT * FROM recurring_routes WHERE driver_id=$1 ORDER BY created_at DESC`, [req.userId]
    );
    const { rows: subscribers } = await pool.query(
      `SELECT s.*, u.name AS hitcher_name, r.from_loc, r.to_loc
       FROM recurring_route_subscribers s
       JOIN recurring_routes r ON r.id=s.route_id
       JOIN users u ON u.id=s.hitcher_id
       WHERE r.driver_id=$1 ORDER BY s.created_at DESC`, [req.userId]
    );
    res.json({ routes, subscribers });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/me/recurring-subscriptions', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT s.*, r.from_loc, r.to_loc, r.days_of_week, r.departure_time, u.name AS driver_name
       FROM recurring_route_subscribers s
       JOIN recurring_routes r ON r.id=s.route_id
       JOIN users u ON u.id=r.driver_id
       WHERE s.hitcher_id=$1 ORDER BY s.created_at DESC`, [req.userId]
    );
    res.json({ subscriptions: rows });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/recurring-routes/:id/join', requireAuth, async (req, res) => {
  try {
    const { rows: routeRows } = await pool.query('SELECT * FROM recurring_routes WHERE id=$1 AND active=true', [req.params.id]);
    const route = routeRows[0];
    if (!route) return res.status(404).json({ error: 'Route not found.' });
    if (route.driver_id === req.userId) return res.status(400).json({ error: "You can't join your own route." });
    const id = crypto.randomUUID();
    try {
      await pool.query(
        `INSERT INTO recurring_route_subscribers (id,route_id,hitcher_id,status,created_at) VALUES ($1,$2,$3,'pending',$4)`,
        [id, route.id, req.userId, now()]
      );
    } catch (err) {
      if (err.code === '23505') return res.status(409).json({ error: "You've already requested to join this route." });
      throw err;
    }
    const { rows: hitcherRows } = await pool.query('SELECT name FROM users WHERE id=$1', [req.userId]);
    await notify(route.driver_id, 'join_request', `${hitcherRows[0]?.name || 'Someone'} wants to join your ${route.from_loc} → ${route.to_loc} regular route.`);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/recurring-routes/:routeId/subscribers/:subId/:action', requireAuth, async (req, res) => {
  try {
    const { routeId, subId, action } = req.params;
    if (!['approve','decline'].includes(action)) return res.status(400).json({ error: 'Invalid action.' });
    const { rows: routeRows } = await pool.query('SELECT * FROM recurring_routes WHERE id=$1', [routeId]);
    const route = routeRows[0];
    if (!route || route.driver_id !== req.userId) return res.status(403).json({ error: 'Only the route owner can do this.' });
    const status = action === 'approve' ? 'approved' : 'declined';
    const { rows: subRows } = await pool.query(
      'UPDATE recurring_route_subscribers SET status=$1 WHERE id=$2 AND route_id=$3 RETURNING hitcher_id', [status, subId, routeId]
    );
    if (subRows[0]) {
      const verb = status === 'approved' ? 'approved you for' : 'declined your request to join';
      await notify(subRows[0].hitcher_id, 'join_response', `The driver ${verb} the ${route.from_loc} → ${route.to_loc} regular route.`);
    }
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/recurring-routes/:id', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM recurring_routes WHERE id=$1', [req.params.id]);
    const route = rows[0];
    if (!route || route.driver_id !== req.userId) return res.status(403).json({ error: 'Only the route owner can do this.' });
    await pool.query('UPDATE recurring_routes SET active=false WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Turns each active recurring route into concrete, bookable `rides` rows for
// the next RECURRING_GENERATION_WINDOW_DAYS days (skipping dates that already
// have an instance), then auto-seats anyone the driver has already approved —
// first-approved-first-seated, up to the route's seat count. For free/petrol
// routes the seat is confirmed immediately; for priced routes the booking is
// created 'pending' and the hitcher completes payment via /bookings/:id/pay.
const RECURRING_GENERATION_WINDOW_DAYS = 10;
async function generateRecurringRideInstances() {
  const { rows: routes } = await pool.query('SELECT * FROM recurring_routes WHERE active=true');
  for (const route of routes) {
    for (let offset = 0; offset < RECURRING_GENERATION_WINDOW_DAYS; offset++) {
      const d = new Date();
      d.setDate(d.getDate() + offset);
      if (!route.days_of_week.includes(d.getDay())) continue;
      const dateStr = d.toISOString().split('T')[0];
      const { rows: existing } = await pool.query(
        'SELECT id FROM rides WHERE recurring_route_id=$1 AND ride_date=$2', [route.id, dateStr]
      );
      if (existing.length > 0) continue;
      const rideId = crypto.randomUUID();
      await pool.query(
        `INSERT INTO rides (id,driver_id,from_loc,to_loc,ride_date,seats_total,seats_available,contribution_type,price_cents,petrol_note,created_at,distance_km,recurring_route_id,departure_time)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
        [rideId, route.driver_id, route.from_loc, route.to_loc, dateStr, route.seats_total, route.seats_total,
         route.contribution_type, route.price_cents, route.petrol_note, now(), route.distance_km, route.id, route.departure_time]
      );
      const { rows: approved } = await pool.query(
        `SELECT * FROM recurring_route_subscribers WHERE route_id=$1 AND status='approved' ORDER BY created_at ASC`,
        [route.id]
      );
      let seatsLeft = route.seats_total;
      for (const sub of approved) {
        if (seatsLeft < 1) break;
        const bookingId = crypto.randomUUID();
        if (route.contribution_type !== 'price') {
          await pool.query(
            `INSERT INTO bookings (id,ride_id,hitcher_id,status,created_at) VALUES ($1,$2,$3,'confirmed',$4)`,
            [bookingId, rideId, sub.hitcher_id, now()]
          );
          seatsLeft -= 1;
          await notify(sub.hitcher_id, 'regular_seat', `Your seat on ${route.from_loc} → ${route.to_loc} for ${dateStr} is confirmed.`);
        } else {
          await pool.query(
            `INSERT INTO bookings (id,ride_id,hitcher_id,status,price_cents,created_at) VALUES ($1,$2,$3,'pending',$4,$5)`,
            [bookingId, rideId, sub.hitcher_id, route.price_cents, now()]
          );
          await notify(sub.hitcher_id, 'regular_seat', `Your seat on ${route.from_loc} → ${route.to_loc} for ${dateStr} is held — pay to confirm it.`);
        }
      }
      if (seatsLeft !== route.seats_total) {
        await pool.query('UPDATE rides SET seats_available=$1 WHERE id=$2', [seatsLeft, rideId]);
      }
    }
  }
}

app.post('/rides/:id/boost', requireAuth, async (req, res) => {
  try {
    const { rows: rideRows } = await pool.query('SELECT * FROM rides WHERE id=$1', [req.params.id]);
    const ride = rideRows[0];
    if (!ride) return res.status(404).json({ error: 'Ride not found.' });
    if (ride.driver_id !== req.userId) return res.status(403).json({ error: 'Only the driver can boost this ride.' });
    const duration = req.body.duration === '7d' ? '7d' : '24h';
    if (duration === '24h') {
      const { rows: userRows } = await pool.query('SELECT boost_credits FROM users WHERE id=$1', [req.userId]);
      const user = userRows[0];
      if (user.boost_credits > 0) {
        const boostedUntil = new Date(Date.now() + 24*60*60*1000).toISOString();
        await pool.query('UPDATE rides SET boosted_until=$1 WHERE id=$2', [boostedUntil, ride.id]);
        await pool.query('UPDATE users SET boost_credits=boost_credits-1 WHERE id=$1', [req.userId]);
        return res.json({ ok: true, usedCredit: true });
      }
    }
    const prices = loadPrices();
    const priceKey = duration === '7d' ? 'boostWeek' : 'boost';
    const priceId = prices[priceKey];
    if (!priceId) return res.status(400).json({ error: 'Run "npm run setup" first.' });
    const session = await stripe.checkout.sessions.create({
      mode: 'payment', line_items: [{ price: priceId, quantity: 1 }],
      metadata: { kind: 'addon', priceKey, rideId: ride.id, duration },
      success_url: `${APP_URL}/?boosted=1`, cancel_url: `${APP_URL}/?cancelled=1`,
    });
    res.json({ url: session.url });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Cancelling within this many hours of departure still frees the seat and
// notifies the driver, but forfeits any refund — so there's no incentive to
// bail right before the driver can realistically fill the seat some other way.
// Only enforced when the ride has both a date and a departure time set; rides
// without one (flexible/no-date listings) have nothing to measure against, so
// they stay freely refundable.
const CANCELLATION_CUTOFF_HOURS = parseInt(process.env.CANCELLATION_CUTOFF_HOURS || '3', 10);
function isLateCancellation(ride) {
  if (!ride.ride_date || !ride.departure_time) return false;
  const departure = new Date(`${ride.ride_date}T${ride.departure_time}:00`);
  if (isNaN(departure.getTime())) return false;
  const hoursUntilDeparture = (departure.getTime() - Date.now()) / (1000 * 60 * 60);
  return hoursUntilDeparture < CANCELLATION_CUTOFF_HOURS;
}

// Lets a hitcher cancel their own booking. Restores the seat and notifies the
// driver either way. If payment already went through AND it's outside the
// cancellation cutoff, reverses both the driver's payout and ridem8's
// facilitator fee via a single Stripe refund; inside the cutoff, no refund.
app.post('/bookings/:id/cancel', requireAuth, async (req, res) => {
  try {
    const { rows: bookingRows } = await pool.query('SELECT * FROM bookings WHERE id=$1', [req.params.id]);
    const booking = bookingRows[0];
    if (!booking) return res.status(404).json({ error: 'Booking not found.' });
    if (booking.hitcher_id !== req.userId) return res.status(403).json({ error: 'Only the person who booked this seat can cancel it.' });
    if (booking.status === 'cancelled') return res.status(400).json({ error: 'This booking is already cancelled.' });
    if (booking.status === 'completed') return res.status(400).json({ error: "This ride's already completed — it can't be cancelled." });

    const { rows: rideRows } = await pool.query('SELECT * FROM rides WHERE id=$1', [booking.ride_id]);
    const ride = rideRows[0];
    const lateCancellation = isLateCancellation(ride);

    let refunded = false;
    if (booking.status === 'paid' && booking.stripe_session_id && !lateCancellation) {
      try {
        const session = await stripe.checkout.sessions.retrieve(booking.stripe_session_id);
        if (session.payment_intent) {
          await stripe.refunds.create({
            payment_intent: session.payment_intent,
            reverse_transfer: true,
            refund_application_fee: true,
          });
          refunded = true;
        }
      } catch (err) {
        console.error('Refund failed for booking', booking.id, err.message);
      }
    }

    await pool.query(`UPDATE bookings SET status='cancelled' WHERE id=$1`, [booking.id]);
    if (booking.status === 'confirmed' || booking.status === 'paid') {
      await pool.query('UPDATE rides SET seats_available=seats_available+1 WHERE id=$1', [ride.id]);
    }
    const { rows: hitcherRows } = await pool.query('SELECT name FROM users WHERE id=$1', [req.userId]);
    const lateNote = lateCancellation ? ' (late cancellation — inside the free-cancellation window)' : '';
    await notify(ride.driver_id, 'cancellation', `${hitcherRows[0]?.name || 'A passenger'} cancelled their seat on your ${ride.from_loc} → ${ride.to_loc} ride${ride.ride_date ? ' on ' + ride.ride_date : ''}${lateNote}.`);
    res.json({ ok: true, refunded, lateCancellation });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/bookings/:id/rate', requireAuth, async (req, res) => {
  try {
    const { stars, comment } = req.body;
    if (!stars||stars<1||stars>5) return res.status(400).json({ error: 'Stars must be 1-5.' });
    if (containsBlockedContent(comment)) return res.status(400).json({ error: 'Please remove inappropriate language from your comment.' });
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
    const reviewsReceived = await pool.query(
      `SELECT rt.*,u.name AS rater_name FROM ratings rt JOIN users u ON u.id=rt.rater_id WHERE rt.ratee_id=$1 ORDER BY rt.created_at DESC`,
      [req.userId]
    );
    const ratingsGiven = await pool.query(
      `SELECT booking_id FROM ratings WHERE rater_id=$1`,
      [req.userId]
    );
    res.json({
      ridesOffered: ridesOffered.rows,
      bookingsAsDriver: bookingsAsDriver.rows,
      bookingsAsHitcher: bookingsAsHitcher.rows,
      reviewsReceived: reviewsReceived.rows,
      ratedBookingIds: ratingsGiven.rows.map(r => r.booking_id),
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

app.get('/notifications', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT * FROM notifications WHERE user_id=$1 ORDER BY created_at DESC LIMIT 30`, [req.userId]
    );
    const { rows: countRows } = await pool.query(
      `SELECT COUNT(*) FROM notifications WHERE user_id=$1 AND read=false`, [req.userId]
    );
    res.json({ notifications: rows, unreadCount: parseInt(countRows[0].count, 10) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/notifications/read-all', requireAuth, async (req, res) => {
  try {
    await pool.query('UPDATE notifications SET read=true WHERE user_id=$1 AND read=false', [req.userId]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/notifications/:id/read', requireAuth, async (req, res) => {
  try {
    await pool.query('UPDATE notifications SET read=true WHERE id=$1 AND user_id=$2', [req.params.id, req.userId]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/config', (req, res) => {
  res.json({ maxReimbursementPerKmCents: MAX_REIMBURSEMENT_PER_KM_CENTS });
});

app.get('/prices', (req, res) => {
  const prices = loadPrices();
  res.json({ ready: Object.keys(prices).length > 0, keys: Object.keys(prices) });
});

const port = process.env.PORT || 4000;
initDb()
  .then(async () => {
    await generateRecurringRideInstances().catch(err => console.error('Recurring route generation failed:', err));
    setInterval(() => {
      generateRecurringRideInstances().catch(err => console.error('Recurring route generation failed:', err));
    }, 60 * 60 * 1000); // hourly is plenty — the window is 10 days deep
    app.listen(port, () => console.log(`ridem8 running on :${port}`));
  })
  .catch(err => {
    console.error('Failed to initialize database:', err);
    process.exit(1);
  });
