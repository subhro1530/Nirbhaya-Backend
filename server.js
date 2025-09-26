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

      CREATE TABLE IF NOT EXISTS guardian_access(
        guardian_id UUID REFERENCES users(id) ON DELETE CASCADE,
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        request_id UUID REFERENCES track_requests(id),
        granted_at TIMESTAMPTZ DEFAULT NOW(),
        PRIMARY KEY (guardian_id, user_id)
      );

      CREATE TABLE IF NOT EXISTS locations(
        id BIGSERIAL PRIMARY KEY,
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        lat DOUBLE PRECISION,
        lng DOUBLE PRECISION,
        accuracy DOUBLE PRECISION,
        recorded_at TIMESTAMPTZ DEFAULT NOW(),
        link TEXT
      );

      CREATE TABLE IF NOT EXISTS track_requests(
        id UUID PRIMARY KEY,
        guardian_id UUID REFERENCES users(id) ON DELETE CASCADE,
        target_user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','denied')),
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
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

    // safe alterations for upgrades
    await client.query(`
      ALTER TABLE guardian_access ADD COLUMN IF NOT EXISTS request_id UUID REFERENCES track_requests(id);
      ALTER TABLE track_requests ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ;
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
    expiresIn: "30d",
  });
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
  res.json({
    accessToken,
    user: { id: user.id, name: user.name, role: user.role },
  });
});

// Lookup email → user ID for guardian
app.get(
  "/users/lookup/email/:email",
  auth(),
  requireRole("guardian"),
  async (req, res) => {
    const email = req.params.email.toLowerCase();
    const r = await pool.query(
      "SELECT id,email,name FROM users WHERE lower(email)=$1",
      [email]
    );
    if (!r.rowCount) return res.status(404).json({ error: "not_found" });
    res.json(r.rows[0]);
  }
);

// Guardian creates track request
app.post(
  "/guardian/track-request",
  auth(),
  requireRole("guardian"),
  async (req, res) => {
    const { targetUserId, targetEmail } = req.body || {};
    let resolvedTargetId = targetUserId || null;

    if (!resolvedTargetId && targetEmail) {
      const q = await pool.query(
        "SELECT id FROM users WHERE lower(email)=lower($1)",
        [targetEmail]
      );
      if (!q.rowCount)
        return res.status(404).json({ error: "target_not_found" });
      resolvedTargetId = q.rows[0].id;
    }

    if (!resolvedTargetId)
      return res
        .status(400)
        .json({ error: "provide targetUserId or targetEmail" });

    if (resolvedTargetId === req.user.id)
      return res.status(400).json({ error: "cannot_request_self" });

    // Only one request ever
    const existing = await pool.query(
      "SELECT id,status FROM track_requests WHERE guardian_id=$1 AND target_user_id=$2 LIMIT 1",
      [req.user.id, resolvedTargetId]
    );
    if (existing.rowCount)
      return res
        .status(409)
        .json({ error: "request_already_exists", request: existing.rows[0] });

    const id = uuid();
    await pool.query(
      "INSERT INTO track_requests(id,guardian_id,target_user_id) VALUES($1,$2,$3)",
      [id, req.user.id, resolvedTargetId]
    );
    res.status(201).json({ id, status: "pending" });
  }
);

// User: list incoming track requests
app.get(
  "/user/track-requests",
  auth(),
  requireRole("user"),
  async (req, res) => {
    const r = await pool.query(
      `SELECT tr.id, tr.status, tr.created_at,
            tr.guardian_id,
            g.name AS guardian_name,
            g.email AS guardian_email
       FROM track_requests tr
       JOIN users g ON g.id = tr.guardian_id
      WHERE tr.target_user_id = $1
      ORDER BY tr.created_at DESC`,
      [req.user.id]
    );
    res.json(
      r.rows.map((row) => ({
        id: row.id,
        status: row.status,
        created_at: row.created_at,
        guardian: {
          id: row.guardian_id,
          name: row.guardian_name,
          email: row.guardian_email,
        },
      }))
    );
  }
);

// server.js (continuing from the previous code)

// 🗄️ Add a "guardianId" to each request (already present above in guardian.id)
let incomingRequests = [
  {
    id: "req1",
    status: "pending",
    created_at: new Date().toISOString(),
    userId: "user_123", // user receiving the request
    guardian: { id: "g_1", name: "Guardian", email: "guardian@example.com" },
  },
  {
    id: "req2",
    status: "approved",
    created_at: new Date().toISOString(),
    userId: "user_123",
    guardian: { id: "g_1", name: "Guardian", email: "guardian@example.com" },
  },
  {
    id: "req3",
    status: "rejected",
    created_at: new Date().toISOString(),
    userId: "user_456",
    guardian: { id: "g_2", name: "Guardian 2", email: "guardian2@example.com" },
  },
];

// Dummy auth for guardians too
function guardianAuth(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  // In a real app decode token:
  // req.guardianId = decoded.guardianId;
  req.guardianId = "g_1"; // hardcoded for demo
  next();
}

// 🔹 Guardian can view the status of the requests they sent
app.get("/guardian/requests", guardianAuth, (req, res) => {
  const myRequests = incomingRequests.filter(
    (r) => r.guardian.id === req.guardianId
  );
  res.json(
    myRequests.map((r) => ({
      id: r.id,
      status: r.status,
      created_at: r.created_at,
      user: { id: r.userId },
    }))
  );
});

// User approves/rejects a track request
app.put(
  "/user/track-request/:id",
  auth(),
  requireRole("user"),
  async (req, res) => {
    const { action } = req.body;
    const requestId = req.params.id;

    if (!["approve", "reject"].includes(action))
      return res.status(400).json({ error: "invalid action" });

    const r = await pool.query(
      "SELECT * FROM track_requests WHERE id=$1 AND target_user_id=$2",
      [requestId, req.user.id]
    );
    if (!r.rowCount)
      return res.status(404).json({ error: "request_not_found" });

    const newStatus = action === "approve" ? "approved" : "denied";

    await pool.query(
      "UPDATE track_requests SET status=$1, updated_at=NOW() WHERE id=$2",
      [newStatus, requestId]
    );

    if (newStatus === "approved") {
      await pool.query(
        "INSERT INTO guardian_access(guardian_id,user_id,request_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING",
        [r.rows[0].guardian_id, req.user.id, requestId]
      );
    }

    res.json({ id: requestId, status: newStatus });
  }
);

// User profile
app.get("/profile/me", auth(), async (req, res) => {
  const r = await pool.query(
    "SELECT id,name,email,role,dob,address,blood_group,emergency_info FROM users WHERE id=$1",
    [req.user.id]
  );
  const profile = r.rows[0] || null;
  if (profile && req.user.role === "user") {
    const tr = await pool.query(
      `SELECT tr.id, tr.status, tr.created_at,
              tr.guardian_id,
              g.name AS guardian_name,
              g.email AS guardian_email
         FROM track_requests tr
         JOIN users g ON g.id = tr.guardian_id
        WHERE tr.target_user_id=$1
        ORDER BY tr.created_at DESC
        LIMIT 50`,
      [req.user.id]
    );
    profile.trackRequests = tr.rows.map((row) => ({
      id: row.id,
      status: row.status,
      created_at: row.created_at,
      guardian: {
        id: row.guardian_id,
        name: row.guardian_name,
        email: row.guardian_email,
      },
    }));
  }
  res.json(profile);
});

// Start server
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server listening on ${port}`));
