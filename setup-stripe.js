// Run once with: npm run setup
// Reads STRIPE_SECRET_KEY and APP_URL from .env, then:
//   1. Creates a Product + Price in Stripe for every paid tier/add-on
//   2. Saves the resulting price IDs to price-ids.json (server.js reads this —
//      you never have to copy/paste a price ID by hand)
//   3. Registers a webhook endpoint pointed at your deployed APP_URL
//   4. Writes the webhook signing secret straight into .env for you
//
// Safe to re-run — it just creates a fresh set each time, which is mainly
// useful when you switch from test keys to live keys before launch.

import Stripe from 'stripe';
import fs from 'fs';
import 'dotenv/config';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const APP_URL = process.env.APP_URL;

if (!process.env.STRIPE_SECRET_KEY || !APP_URL) {
  console.error('Missing STRIPE_SECRET_KEY or APP_URL in .env — fill those in first.');
  process.exit(1);
}

async function createPrice(name, unitAmount, currency, recurring) {
  const product = await stripe.products.create({ name });
  const price = await stripe.prices.create({
    product: product.id,
    unit_amount: unitAmount,
    currency,
    ...(recurring ? { recurring } : {}),
  });
  console.log(`  ✓ ${name} — ${(unitAmount / 100).toFixed(2)} ${currency.toUpperCase()}${recurring ? ' /' + recurring.interval : ''}`);
  return price.id;
}

function saveWebhookSecret(secret) {
  let env = fs.existsSync('.env') ? fs.readFileSync('.env', 'utf8') : '';
  if (env.includes('STRIPE_WEBHOOK_SECRET=')) {
    env = env.replace(/STRIPE_WEBHOOK_SECRET=.*/g, `STRIPE_WEBHOOK_SECRET=${secret}`);
  } else {
    env += `\nSTRIPE_WEBHOOK_SECRET=${secret}\n`;
  }
  fs.writeFileSync('.env', env);
}

async function main() {
  console.log('Creating products & prices in Stripe...');
  const prices = {
    driverPlusMonthly: await createPrice('Driver Plus (monthly)', 600, 'nzd', { interval: 'month' }),
    driverPlusAnnual: await createPrice('Driver Plus (annual)', 5800, 'nzd', { interval: 'year' }),
    roadTripperAnnual: await createPrice('Road Tripper (annual)', 6000, 'nzd', { interval: 'year' }),
    boost: await createPrice('Listing boost (24h)', 200, 'nzd', null),
    insurance: await createPrice('Per-ride insurance', 300, 'nzd', null),
    verification: await createPrice('Instant verification', 400, 'nzd', null),
  };
  fs.writeFileSync('./price-ids.json', JSON.stringify(prices, null, 2));
  console.log('Saved price-ids.json\n');

  console.log(`Registering webhook endpoint at ${APP_URL}/webhook ...`);
  const endpoint = await stripe.webhookEndpoints.create({
    url: `${APP_URL}/webhook`,
    enabled_events: ['checkout.session.completed', 'account.updated'],
  });
  saveWebhookSecret(endpoint.secret);
  console.log('Webhook registered and secret saved to .env\n');

  console.log('All done. Restart your server so it picks up the new .env value.');
  console.log(`Using ${process.env.STRIPE_SECRET_KEY.startsWith('sk_live') ? 'LIVE' : 'TEST'} mode keys.`);
}

main().catch((err) => {
  console.error('Setup failed:', err.message);
  process.exit(1);
});
