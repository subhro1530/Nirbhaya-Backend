require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const compression = require("compression");
const morgan = require("morgan");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { v4: uuid } = require("uuid");

const app = express();
app.use(helmet());
app.use(cors());
app.use(compression());
app.use(express.json({ limit: "512kb" }));
app.use(morgan(process.env.NODE_ENV === "production" ? "combined" : "dev"));

// Postgres connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.PGSSLMODE === "require"
      ? { rejectUnauthorized: false }
      : undefined,
});

pool.on("connect", () => console.log("Postgres connected"));

// --- DB Initialization ---
async function initDb() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users(
        id UUID PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('user','guardian','ngo','admin')),
        dob DATE,
        phone TEXT,
        address TEXT,
        blood_group TEXT,
        emergency_info TEXT,
        org_name TEXT,
        contact_person TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS refresh_tokens(
        id UUID PRIMARY KEY,
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        token TEXT NOT NULL,
        revoked BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS guardian_access(
        guardian_id UUID REFERENCES users(id) ON DELETE CASCADE,
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        granted_at TIMESTAMPTZ DEFAULT NOW(),
        PRIMARY KEY (guardian_id, user_id)
      );
      CREATE TABLE IF NOT EXISTS locations(
        id BIGSERIAL PRIMARY KEY,
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        link TEXT NOT NULL,
        recorded_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS track_requests(
        id UUID PRIMARY KEY,
        guardian_id UUID REFERENCES users(id) ON DELETE CASCADE,
        target_user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','denied')),
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS sos(
        id UUID PRIMARY KEY,
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        note TEXT,
        emergency_type TEXT,
        active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        resolved_at TIMESTAMPTZ
      );
      CREATE TABLE IF NOT EXISTS doctors(
        id UUID PRIMARY KEY,
        ngo_id UUID REFERENCES users(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        phone TEXT,
        specialty TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);
    // --- schema migration for existing older users table ---
    await client.query(`
      ALTER TABLE users
        ADD COLUMN IF NOT EXISTS dob DATE,
        ADD COLUMN IF NOT EXISTS phone TEXT,
        ADD COLUMN IF NOT EXISTS address TEXT,
        ADD COLUMN IF NOT EXISTS blood_group TEXT,
        ADD COLUMN IF NOT EXISTS emergency_info TEXT,
        ADD COLUMN IF NOT EXISTS org_name TEXT,
        ADD COLUMN IF NOT EXISTS contact_person TEXT;
    `);
    console.log("DB schema initialized");
  } finally {
    client.release();
  }
}
initDb().catch((e) => {
  console.error(e);
  process.exit(1);
});

// --- JWT Helpers ---
function signAccessToken(user) {
  return jwt.sign({ sub: user.id, role: user.role }, process.env.JWT_SECRET, {
    expiresIn: "15m",
  });
}
function signRefreshToken(user) {
  return jwt.sign(
    { sub: user.id, type: "refresh" },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: "30d" }
  );
}

// --- Middleware ---
function auth(required = true) {
  return (req, res, next) => {
    const header = req.headers.authorization;
    if (!header) {
      if (!required) return next();
      return res.status(401).json({ error: "missing authorization" });
    }
    const token = header.replace(/^Bearer\s+/i, "");
    try {
      const payload = jwt.verify(token, process.env.JWT_SECRET);
      req.user = { id: payload.sub, role: payload.role };
      next();
    } catch {
      return res.status(401).json({ error: "invalid token" });
    }
  };
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: "unauthorized" });
    if (!roles.includes(req.user.role))
      return res.status(403).json({ error: "forbidden" });
    next();
  };
}

// --- Helper Functions ---
async function canViewUser(requesterId, requesterRole, targetUserId) {
  if (requesterRole === "admin" || requesterRole === "ngo") return true;
  if (requesterRole === "guardian") {
    const r = await pool.query(
      "SELECT 1 FROM guardian_access WHERE guardian_id=$1 AND user_id=$2",
      [requesterId, targetUserId]
    );
    return !!r.rowCount;
  }
  return requesterId === targetUserId;
}

// --- Routes ---

// Health
app.get("/health", (_req, res) => res.json({ status: "ok" }));

// Auth
app.post("/auth/sign-up", async (req, res) => {
  const { name, email, password, role } = req.body;
  if (!name || !email || !password || !role)
    return res.status(400).json({ error: "missing fields" });
  const exists = await pool.query("SELECT 1 FROM users WHERE email=$1", [
    email,
  ]);
  if (exists.rowCount) return res.status(409).json({ error: "email_in_use" });
  const hash = await bcrypt.hash(password, 10);
  const id = uuid();
  await pool.query(
    "INSERT INTO users(id,name,email,password_hash,role) VALUES($1,$2,$3,$4,$5)",
    [id, name, email, hash, role]
  );
  res.status(201).json({ id, name, email, role });
});

app.post("/auth/sign-in", async (req, res) => {
  const { email, password } = req.body;
  const r = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
  if (!r.rowCount)
    return res.status(401).json({ error: "invalid credentials" });
  const user = r.rows[0];
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: "invalid credentials" });
  const accessToken = signAccessToken(user);
  const refreshToken = signRefreshToken(user);
  await pool.query(
    "INSERT INTO refresh_tokens(id,user_id,token) VALUES($1,$2,$3)",
    [uuid(), user.id, refreshToken]
  );
  res.json({
    accessToken,
    refreshToken,
    user: { id: user.id, name: user.name, role: user.role },
  });
});

// Profile
app.get("/profile/me", auth(), async (req, res) => {
  const r = await pool.query(
    "SELECT id,name,email,role,dob,address,blood_group,emergency_info FROM users WHERE id=$1",
    [req.user.id]
  );
  res.json(r.rows[0]);
});
app.put("/profile/me", auth(), async (req, res) => {
  const { dob, address, blood_group, emergency_info } = req.body;
  await pool.query(
    "UPDATE users SET dob=COALESCE($2,dob), address=COALESCE($3,address), blood_group=COALESCE($4,blood_group), emergency_info=COALESCE($5,emergency_info) WHERE id=$1",
    [req.user.id, dob, address, blood_group, emergency_info]
  );
  const updated = await pool.query(
    "SELECT id,name,email,role,dob,address,blood_group,emergency_info FROM users WHERE id=$1",
    [req.user.id]
  );
  res.json(updated.rows[0]);
});

// Guardian requests
app.post(
  "/guardian/track-request",
  auth(),
  requireRole("guardian"),
  async (req, res) => {
    const { targetUserId } = req.body;
    const id = uuid();
    await pool.query(
      "INSERT INTO track_requests(id,guardian_id,target_user_id) VALUES($1,$2,$3)",
      [id, req.user.id, targetUserId]
    );
    res.status(201).json({ id, status: "pending" });
  }
);

app.post(
  "/user/track-request/:requestId/respond",
  auth(),
  requireRole("user"),
  async (req, res) => {
    const { approved } = req.body;
    const { requestId } = req.params;
    const r = await pool.query("SELECT * FROM track_requests WHERE id=$1", [
      requestId,
    ]);
    if (!r.rowCount) return res.status(404).json({ error: "not found" });
    const reqRow = r.rows[0];
    if (reqRow.target_user_id !== req.user.id)
      return res.status(403).json({ error: "forbidden" });
    const status = approved ? "approved" : "denied";
    await pool.query("UPDATE track_requests SET status=$2 WHERE id=$1", [
      requestId,
      status,
    ]);
    if (approved)
      await pool.query(
        "INSERT INTO guardian_access(guardian_id,user_id) VALUES($1,$2) ON CONFLICT DO NOTHING",
        [reqRow.guardian_id, reqRow.target_user_id]
      );
    res.json({ status });
  }
);

// Locations
app.post("/locations", auth(), requireRole("user"), async (req, res) => {
  const { link } = req.body;
  if (!link) return res.status(400).json({ error: "missing link" });
  await pool.query("INSERT INTO locations(user_id,link) VALUES($1,$2)", [
    req.user.id,
    link,
  ]);
  res.status(201).json({ success: true });
});
app.get("/locations/latest/:userId", auth(), async (req, res) => {
  if (!(await canViewUser(req.user.id, req.user.role, req.params.userId)))
    return res.status(403).json({ error: "forbidden" });
  const r = await pool.query(
    "SELECT link,recorded_at FROM locations WHERE user_id=$1 ORDER BY recorded_at DESC LIMIT 1",
    [req.params.userId]
  );
  if (!r.rowCount) return res.status(404).json({ error: "not found" });
  res.json(r.rows[0]);
});

// SOS
app.post("/sos", auth(), requireRole("user"), async (req, res) => {
  const { note, emergency_type } = req.body;
  const id = uuid();
  await pool.query(
    "INSERT INTO sos(id,user_id,note,emergency_type) VALUES($1,$2,$3,$4)",
    [id, req.user.id, note, emergency_type]
  );
  res.status(201).json({ id, active: true });
});
app.get("/sos/:id", auth(), async (req, res) => {
  const r = await pool.query("SELECT * FROM sos WHERE id=$1", [req.params.id]);
  if (!r.rowCount) return res.status(404).json({ error: "not found" });
  res.json(r.rows[0]);
});

// NGOs & Doctors
app.post("/doctors", auth(), requireRole("ngo"), async (req, res) => {
  const { name, phone, specialty } = req.body;
  const id = uuid();
  await pool.query(
    "INSERT INTO doctors(id,ngo_id,name,phone,specialty) VALUES($1,$2,$3,$4,$5)",
    [id, req.user.id, name, phone, specialty]
  );
  res.status(201).json({ id });
});

// Visibility endpoints
app.get("/profile/me/visible-to", auth(), async (req, res) => {
  if (req.user.role !== "user") return res.json({ visibleTo: [] });
  const r = await pool.query(
    "SELECT guardian_id FROM guardian_access WHERE user_id=$1",
    [req.user.id]
  );
  res.json({ visibleTo: r.rows.map((x) => x.guardian_id) });
});
app.get(
  "/profile/me/access-to",
  auth(),
  requireRole("guardian", "ngo"),
  async (req, res) => {
    if (req.user.role === "guardian") {
      const r = await pool.query(
        "SELECT user_id FROM guardian_access WHERE guardian_id=$1",
        [req.user.id]
      );
      res.json({ canAccess: r.rows.map((x) => x.user_id) });
    } else res.json({ canAccess: [] });
  }
);

// --- Start Server ---
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Nirbhaya backend running on ${port}`));

module.exports = { app, pool };
