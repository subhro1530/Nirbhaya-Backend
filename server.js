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

// --- Postgres connection ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.PGSSLMODE === "require"
      ? { rejectUnauthorized: false }
      : undefined,
});

pool.on("connect", () => console.log("Postgres connected"));

// Simple UUID check (moved near top for reuse)
function isUUID(v) {
  return (
    typeof v === "string" &&
    /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/.test(
      v
    )
  );
}

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

      CREATE TABLE IF NOT EXISTS track_requests(
        id UUID PRIMARY KEY,
        guardian_id UUID REFERENCES users(id) ON DELETE CASCADE,
        target_user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','denied')),
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
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

    // Deduplicate track_requests before unique index (keep earliest)
    await client.query(`
      WITH ranked AS (
        SELECT ctid, guardian_id, target_user_id,
               ROW_NUMBER() OVER (PARTITION BY guardian_id,target_user_id ORDER BY created_at ASC) rn
        FROM track_requests
      )
      DELETE FROM track_requests t
      USING ranked r
      WHERE t.ctid = r.ctid AND r.rn > 1;
    `);
    await client.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS track_requests_guardian_target_unique
        ON track_requests(guardian_id, target_user_id);
    `);

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

// 🔹 Upload current location link (user)
app.post("/location/upload", auth(), requireRole("user"), async (req, res) => {
  try {
    const { link } = req.body || {};
    if (!link) return res.status(400).json({ error: "missing link" });

    const r = await pool.query(
      `INSERT INTO locations(user_id, link)
       VALUES($1,$2)
       RETURNING id, recorded_at`,
      [req.user.id, link]
    );

    res.status(201).json({
      id: r.rows[0].id,
      recorded_at: r.rows[0].recorded_at,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "internal_error" });
  }
});

// 🔹 List uploaded location links (user)
app.get("/location/mine", auth(), requireRole("user"), async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT id, link, recorded_at
         FROM locations
        WHERE user_id=$1
        ORDER BY recorded_at DESC`,
      [req.user.id]
    );
    res.json(r.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "internal_error" });
  }
});

// 🔹 Guardian fetches last recorded location of a user (add UUID validation)
app.get(
  "/guardian/user-location/:userId",
  auth(),
  requireRole("guardian"),
  async (req, res) => {
    const targetUserId = req.params.userId;
    if (!isUUID(targetUserId)) {
      return res.status(400).json({ error: "invalid_user_id" });
    }

    const access = await pool.query(
      "SELECT 1 FROM guardian_access WHERE guardian_id=$1 AND user_id=$2",
      [req.user.id, targetUserId]
    );
    if (!access.rowCount)
      return res.status(403).json({ error: "no_access_to_user" });

    const location = await pool.query(
      `SELECT id, lat, lng, accuracy, link, recorded_at
       FROM locations
       WHERE user_id=$1
       ORDER BY recorded_at DESC
       LIMIT 1`,
      [targetUserId]
    );

    if (!location.rowCount)
      return res.status(404).json({ error: "no_location_found" });

    res.json(location.rows[0]);
  }
);

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
    let resolvedTargetId = null;

    if (targetEmail) {
      const q = await pool.query(
        "SELECT id FROM users WHERE lower(email)=lower($1)",
        [targetEmail]
      );
      if (!q.rowCount)
        return res.status(404).json({ error: "target_not_found" });
      resolvedTargetId = q.rows[0].id;
    } else if (targetUserId) {
      // Prevent passing a JWT token (or any non-uuid) in place of user id
      if (!isUUID(targetUserId)) {
        return res.status(400).json({
          error: "invalid_target_user_id",
          hint: "Provide a valid UUID in targetUserId or use targetEmail instead",
        });
      }
      resolvedTargetId = targetUserId;
    } else {
      return res
        .status(400)
        .json({ error: "provide targetUserId or targetEmail" });
    }

    if (resolvedTargetId === req.user.id)
      return res.status(400).json({ error: "cannot_request_self" });

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
    } else {
      await pool.query("DELETE FROM guardian_access WHERE request_id=$1", [
        requestId,
      ]);
    }

    res.json({ id: requestId, status: newStatus });
  }
);

// Guardian can view status of requests they sent
app.get(
  "/guardian/requests",
  auth(),
  requireRole("guardian"),
  async (req, res) => {
    const r = await pool.query(
      `SELECT tr.id, tr.status, tr.created_at, tr.updated_at,
              tr.target_user_id AS user_id,
              u.name AS user_name, u.email AS user_email
         FROM track_requests tr
         JOIN users u ON u.id = tr.target_user_id
        WHERE tr.guardian_id = $1
        ORDER BY tr.created_at DESC`,
      [req.user.id]
    );
    res.json(
      r.rows.map((row) => ({
        id: row.id,
        status: row.status,
        created_at: row.created_at,
        updated_at: row.updated_at,
        user: {
          id: row.user_id,
          name: row.user_name,
          email: row.user_email,
        },
      }))
    );
  }
);

// Guardian cancels (deletes) a request
app.delete(
  "/guardian/track-request/:id",
  auth(),
  requireRole("guardian"),
  async (req, res) => {
    const requestId = req.params.id;
    const r = await pool.query(
      "SELECT * FROM track_requests WHERE id=$1 AND guardian_id=$2",
      [requestId, req.user.id]
    );
    if (!r.rowCount)
      return res.status(404).json({ error: "request_not_found" });

    await pool.query("DELETE FROM track_requests WHERE id=$1", [requestId]);
    await pool.query("DELETE FROM guardian_access WHERE request_id=$1", [
      requestId,
    ]);

    res.json({ deleted: requestId });
  }
);

// User revokes an already granted guardian access
app.delete(
  "/user/access/:guardianId",
  auth(),
  requireRole("user"),
  async (req, res) => {
    const guardianId = req.params.guardianId;
    await pool.query(
      "DELETE FROM guardian_access WHERE guardian_id=$1 AND user_id=$2",
      [guardianId, req.user.id]
    );
    res.json({ revoked: guardianId });
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

// 🔹 Resolve email → user id and role
app.get("/resolve/user", auth(), async (req, res) => {
  const email = req.query.email;
  const r = await pool.query(
    "SELECT id, name, email, role FROM users WHERE email=$1",
    [email]
  );
  if (!r.rowCount) return res.status(404).json({ error: "not_found" });
  res.json(r.rows[0]);
});

// 🔹 Resolve guardian id → info (name/email)
app.get("/resolve/guardian/:id", auth(), async (req, res) => {
  const id = req.params.id;
  const r = await pool.query(
    "SELECT id, name, email FROM users WHERE id=$1 AND role='guardian'",
    [id]
  );
  if (!r.rowCount) return res.status(404).json({ error: "not_found" });
  res.json(r.rows[0]);
});

// --- Location ingestion alias (/locations) & latest/history retrieval ---

// (Alias) Accept lat/lng or link
app.post("/locations", auth(), requireRole("user"), async (req, res) => {
  const { link, lat, lng, accuracy } = req.body || {};
  if (!link && (typeof lat !== "number" || typeof lng !== "number")) {
    return res.status(400).json({ error: "provide_link_or_lat_lng" });
  }
  try {
    const r = await pool.query(
      `INSERT INTO locations(user_id, link, lat, lng, accuracy)
       VALUES($1,$2,$3,$4,$5)
       RETURNING id, recorded_at`,
      [
        req.user.id,
        link || null,
        typeof lat === "number" ? lat : null,
        typeof lng === "number" ? lng : null,
        typeof accuracy === "number" ? accuracy : null,
      ]
    );
    res
      .status(201)
      .json({ id: r.rows[0].id, recorded_at: r.rows[0].recorded_at });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "internal_error" });
  }
});

// Latest location (user self or guardian with access)
app.get("/locations/latest/:userId", auth(), async (req, res) => {
  const targetUserId = req.params.userId;
  if (!isUUID(targetUserId)) {
    return res.status(400).json({ error: "invalid_user_id" });
  }
  // Permission: self or guardian_access or (future: ngo/admin)
  if (req.user.id !== targetUserId) {
    if (req.user.role === "guardian") {
      const a = await pool.query(
        "SELECT 1 FROM guardian_access WHERE guardian_id=$1 AND user_id=$2",
        [req.user.id, targetUserId]
      );
      if (!a.rowCount) return res.status(403).json({ error: "forbidden" });
    } else if (!["admin", "ngo"].includes(req.user.role)) {
      return res.status(403).json({ error: "forbidden" });
    }
  }
  const r = await pool.query(
    `SELECT id, link, lat, lng, accuracy, recorded_at
       FROM locations
      WHERE user_id=$1
      ORDER BY recorded_at DESC
      LIMIT 1`,
    [targetUserId]
  );
  if (!r.rowCount) return res.status(404).json({ error: "no_location_found" });
  res.json(r.rows[0]);
});

// Location history with optional time window
app.get("/locations/history/:userId", auth(), async (req, res) => {
  const targetUserId = req.params.userId;
  if (!isUUID(targetUserId)) {
    return res.status(400).json({ error: "invalid_user_id" });
  }
  // Permission logic same as latest
  if (req.user.id !== targetUserId) {
    if (req.user.role === "guardian") {
      const a = await pool.query(
        "SELECT 1 FROM guardian_access WHERE guardian_id=$1 AND user_id=$2",
        [req.user.id, targetUserId]
      );
      if (!a.rowCount) return res.status(403).json({ error: "forbidden" });
    } else if (!["admin", "ngo"].includes(req.user.role)) {
      return res.status(403).json({ error: "forbidden" });
    }
  }
  const { from, to, limit = 100 } = req.query;
  const params = [targetUserId];
  let where = "user_id=$1";
  if (from) {
    params.push(new Date(from));
    where += ` AND recorded_at >= $${params.length}`;
  }
  if (to) {
    params.push(new Date(to));
    where += ` AND recorded_at <= $${params.length}`;
  }
  params.push(Math.min(parseInt(limit, 10) || 100, 500));
  const r = await pool.query(
    `SELECT id, link, lat, lng, accuracy, recorded_at
       FROM locations
      WHERE ${where}
      ORDER BY recorded_at DESC
      LIMIT $${params.length}`,
    params
  );
  res.json(r.rows);
});

// --- Start server ---
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server listening on ${port}`));
