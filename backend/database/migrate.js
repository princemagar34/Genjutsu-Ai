// ============================================================
// database/migrate.js
// Run ONCE to migrate existing SQLite data → PostgreSQL
// Usage: node database/migrate.js
// ============================================================
require('dotenv').config();
const Database = require('better-sqlite3');
const { Pool } = require('pg');
const path = require('path');

const sqlite = new Database(path.join(__dirname, 'genjutsu.db'));
const pg = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

// Tables to migrate in order (respects foreign keys)
const TABLES = [
  'users',
  'ml_models',
  'emails',
  'scan_results',
  'alerts',
  'honeypot_sessions',
  'honeypot_messages',
  'user_settings',
  'admin_users',
  'threat_reviews',
  'activity_log',
  'system_settings',
  'suspended_users',
  'threat_overrides',
];

async function migrate() {
  console.log('🚀 Starting SQLite → PostgreSQL migration...\n');

  for (const table of TABLES) {
    try {
      const rows = sqlite.prepare(`SELECT * FROM ${table}`).all();
      if (rows.length === 0) {
        console.log(`  ⏭  ${table}: empty, skipping`);
        continue;
      }

      const cols = Object.keys(rows[0]);
      let inserted = 0;
      let skipped  = 0;

      for (const row of rows) {
        const placeholders = cols.map((_, i) => `$${i + 1}`).join(', ');
        const values = cols.map(c => row[c]);
        try {
          await pg.query(
            `INSERT INTO ${table} (${cols.join(', ')}) VALUES (${placeholders}) ON CONFLICT DO NOTHING`,
            values
          );
          inserted++;
        } catch (err) {
          skipped++;
          // uncomment to debug: console.error(`    ⚠ Row skipped in ${table}:`, err.message);
        }
      }

      console.log(`  ✅ ${table}: ${inserted} inserted, ${skipped} skipped`);
    } catch (err) {
      console.error(`  ❌ ${table} failed:`, err.message);
    }
  }

  console.log('\n✅ Migration complete!');
  await pg.end();
  sqlite.close();
}

migrate().catch(err => {
  console.error('Migration failed:', err);
  process.exit(1);
});
