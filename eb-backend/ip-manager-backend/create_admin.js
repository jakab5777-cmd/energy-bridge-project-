const { Pool } = require('pg');

let bcrypt;
try { bcrypt = require('bcrypt'); } 
catch (e) { bcrypt = require('bcryptjs'); }

const pool = new Pool({
  host: '127.0.0.1',
  port: 5432,
  user: 'isp',
  password: 'Energy@SYSAD@2025@A', // <--- Put your actual database password here
  database: 'ispdb'
});

async function createAdmin() {
  try {
    console.log("Hashing password...");
    
    // CHANGE THIS to your desired web login password
    const webPassword = 'SYSAD@2025@A';
    const hashedPassword = await bcrypt.hash(webPassword, 10);

    console.log("Inserting admin into database...");
    
    // Updated query to match your table columns: password_hash
    await pool.query(`
      INSERT INTO ip_manager_users (username, password_hash, role) 
      VALUES ('admin', $1, 'admin')
      ON CONFLICT (username) DO UPDATE SET password_hash = $1;
    `, [hashedPassword]);

    console.log("✅ Success! Admin user created.");
  } catch (error) {
    console.error("❌ Error:", error.message);
  } finally {
    pool.end();
  }
}

createAdmin();
