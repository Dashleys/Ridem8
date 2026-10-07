// One-off migration: creates trip_records (Land Transport Act s30Q records)
// Run from repo root:  node migrate_trip_records.js
require('dotenv').config();
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

const SQL = `
CREATE TABLE IF NOT EXISTS trip_records (
  id                        SERIAL PRIMARY KEY,
  ride_id                   INTEGER NOT NULL,
  booking_id                INTEGER,
  driver_id                 INTEGER NOT NULL,
  passenger_id              INTEGER NOT NULL,
  trip_date                 TIMESTAMPTZ NOT NULL,
  origin                    TEXT NOT NULL,
  destination               TEXT NOT NULL,
  distance_km               NUMERIC(8,2) NOT NULL CHECK (distance_km > 0),
  seats                     INTEGER NOT NULL DEFAULT 1 CHECK (seats > 0),
  rate_cents_per_km         INTEGER NOT NULL CHECK (rate_cents_per_km > 0),
  driver_payout_cents       INTEGER NOT NULL CHECK (driver_payout_cents >= 0),
  facilitator_fee_cents     INTEGER NOT NULL CHECK (facilitator_fee_cents >= 0),
  passenger_paid_cents      INTEGER NOT NULL CHECK (passenger_paid_cents >= 0),
  stripe_payment_intent_id  TEXT UNIQUE,
  stripe_transfer_id        TEXT,
  created_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT payment_split CHECK (passenger_paid_cents = driver_payout_cents + facilitator_fee_cents),
  CONSTRAINT payout_within_cap CHECK (driver_payout_cents <= ROUND(distance_km * rate_cents_per_km))
);

CREATE INDEX IF NOT EXISTS idx_trip_records_ride   ON trip_records (ride_id);
CREATE INDEX IF NOT EXISTS idx_trip_records_driver ON trip_records (driver_id);
CREATE INDEX IF NOT EXISTS idx_trip_records_date   ON trip_records (trip_date);

-- Cap applies to the whole ride: total paid to the driver across ALL passengers <= distance x rate
CREATE OR REPLACE FUNCTION enforce_ride_payout_cap() RETURNS trigger AS $$
DECLARE
  existing_total INTEGER;
  cap INTEGER;
BEGIN
  PERFORM pg_advisory_xact_lock(NEW.ride_id);
  SELECT COALESCE(SUM(driver_payout_cents), 0) INTO existing_total
    FROM trip_records
   WHERE ride_id = NEW.ride_id AND id IS DISTINCT FROM NEW.id;
  cap := ROUND(NEW.distance_km * NEW.rate_cents_per_km);
  IF existing_total + NEW.driver_payout_cents > cap THEN
    RAISE EXCEPTION 'Ride % payout cap exceeded: % + % > % cents',
      NEW.ride_id, existing_total, NEW.driver_payout_cents, cap;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_ride_payout_cap ON trip_records;
CREATE TRIGGER trg_ride_payout_cap
  BEFORE INSERT OR UPDATE ON trip_records
  FOR EACH ROW EXECUTE FUNCTION enforce_ride_payout_cap();

-- Records are evidence: block deletes (12-month retention minimum)
CREATE OR REPLACE FUNCTION block_trip_record_delete() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'trip_records are retained for compliance and cannot be deleted';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_block_trip_record_delete ON trip_records;
CREATE TRIGGER trg_block_trip_record_delete
  BEFORE DELETE ON trip_records
  FOR EACH ROW EXECUTE FUNCTION block_trip_record_delete();
`;

(async () => {
  try {
    await pool.query(SQL);
    console.log('trip_records ready');
  } catch (err) {
    console.error('Migration failed:', err.message);
    process.exitCode = 1;
  } finally {
    await pool.end();
  }
})();
