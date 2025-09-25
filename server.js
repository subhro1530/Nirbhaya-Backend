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

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.PGSSLMODE === "require"
      ? { rejectUnauthorized: false }
      : undefined,
});
// Added simple connect log
pool.on("connect", () => console.log("PostgreSQL pool connected"));

async function initDb() {
  const client = await pool.connect();
  try {
    await client.query(`
      create table if not exists users(
        id uuid primary key,
        name text not null,
        email text unique not null,
        password_hash text not null,
        role text not null check(role in ('user','guardian','ngo','admin')),
        phone text,
        address text,
        meta jsonb default '{}'::jsonb,
        org_name text,
        contact_person text,
        created_at timestamptz default now()
      );
      create table if not exists refresh_tokens(
        id uuid primary key,
        user_id uuid references users(id) on delete cascade,
        token text not null,
        created_at timestamptz default now(),
        revoked boolean default false
      );
      create table if not exists trusted_contacts(
        id uuid primary key,
        user_id uuid references users(id) on delete cascade,
        name text not null,
        relation text,
        phone text,
        email text,
        guardian_id uuid references users(id),
        created_at timestamptz default now()
      );
      create table if not exists track_requests(
        id uuid primary key,
        guardian_id uuid references users(id) on delete cascade,
        target_user_id uuid references users(id) on delete cascade,
        message text,
        status text not null default 'pending' check(status in ('pending','approved','denied')),
        created_at timestamptz default now()
      );
      create table if not exists guardian_access(
        guardian_id uuid references users(id) on delete cascade,
        user_id uuid references users(id) on delete cascade,
        granted_at timestamptz default now(),
        primary key(guardian_id,user_id)
      );
      create table if not exists locations(
        id bigserial primary key,
        user_id uuid references users(id) on delete cascade,
        lat double precision not null,
        lng double precision not null,
        accuracy double precision,
        recorded_at timestamptz default now()
      );
      create table if not exists sos(
        id uuid primary key,
        user_id uuid references users(id) on delete cascade,
        lat double precision,
        lng double precision,
        note text,
        emergency_type text,
        active boolean default true,
        created_at timestamptz default now(),
        resolved_at timestamptz
      );
      create table if not exists doctors(
        id uuid primary key,
        ngo_id uuid references users(id) on delete cascade,
        name text not null,
        phone text,
        specialty text,
        lat double precision,
        lng double precision,
        created_at timestamptz default now()
      );
    `);
    console.log("Database schema ensured");
    if (process.env.SEED_ADMIN === "true") {
      const adminEmail = process.env.ADMIN_EMAIL || "admin@example.com";
      const exists = await client.query("select 1 from users where email=$1", [
        adminEmail,
      ]);
      if (!exists.rowCount) {
        const id = uuid();
        const hash = await bcrypt.hash(
          process.env.ADMIN_PASSWORD || "ChangeMe123!",
          10
        );
        await client.query(
          "insert into users(id,name,email,password_hash,role) values($1,$2,$3,$4,$5)",
          [id, "Platform Admin", adminEmail, hash, "admin"]
        );
        console.log("Seeded admin:", adminEmail);
      }
    }
  } finally {
    client.release();
  }
}
initDb().catch((e) => {
  console.error("DB init failed", e);
  process.exit(1);
});

// Helpers
function signAccessToken(user) {
  return jwt.sign({ sub: user.id, role: user.role }, process.env.JWT_SECRET, {
    expiresIn: "15m",
  });
}
function signRefreshToken(user) {
  return jwt.sign(
    { sub: user.id, role: user.role, type: "refresh" },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: "30d" }
  );
}
async function storeRefreshToken(userId, token) {
  await pool.query(
    "insert into refresh_tokens(id,user_id,token) values($1,$2,$3)",
    [uuid(), userId, token]
  );
}
async function verifyRefreshToken(token) {
  let payload;
  try {
    payload = jwt.verify(token, process.env.JWT_REFRESH_SECRET);
  } catch {
    return null;
  }
  const row = await pool.query(
    "select * from refresh_tokens where token=$1 and revoked=false",
    [token]
  );
  if (!row.rowCount) return null;
  return payload;
}

async function getUserById(id) {
  const r = await pool.query(
    "select id,name,email,role,phone,address,meta,org_name,contact_person from users where id=$1",
    [id]
  );
  return r.rows[0];
}

// Middleware
function auth(required = true) {
  return (req, res, next) => {
    const header = req.headers.authorization;
    if (!header) {
      if (!required) return next();
      return res.status(401).json({ error: "missing authorization header" });
    }
    const token = header.replace(/^Bearer\s+/i, "");
    try {
      const payload = jwt.verify(token, process.env.JWT_SECRET);
      req.user = { id: payload.sub, role: payload.role };
      next();
    } catch {
      return res.status(401).json({ error: "invalid_token" });
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
async function canViewLocation(requesterId, requesterRole, targetUserId) {
  if (requesterId === targetUserId) return true;
  if (requesterRole === "admin" || requesterRole === "ngo") return true; // refine as needed
  if (requesterRole === "guardian") {
    const r = await pool.query(
      "select 1 from guardian_access where guardian_id=$1 and user_id=$2",
      [requesterId, targetUserId]
    );
    return !!r.rowCount;
  }
  return false;
}

// Routes

// Health & version
app.get("/health", (_req, res) =>
  res.json({ status: "ok", time: new Date().toISOString() })
);
app.get("/version", (_req, res) => res.json({ version: "0.1.0" }));

// Auth
app.post("/auth/sign-up", async (req, res, next) => {
  try {
    const { name, email, password, role } = req.body || {};
    if (!name || !email || !password || !role)
      return res.status(400).json({ error: "missing_fields" });
    if (!["user", "guardian", "ngo"].includes(role))
      return res.status(400).json({ error: "invalid_role" });
    const exists = await pool.query("select 1 from users where email=$1", [
      email,
    ]);
    if (exists.rowCount) return res.status(409).json({ error: "email_in_use" });
    const hash = await bcrypt.hash(password, 10);
    const id = uuid();
    await pool.query(
      "insert into users(id,name,email,password_hash,role) values($1,$2,$3,$4,$5)",
      [id, name, email, hash, role]
    );
    res.status(201).json({ id, name, email, role });
  } catch (e) {
    next(e);
  }
});

app.post("/auth/sign-in", async (req, res, next) => {
  try {
    const { email, password, role } = req.body || {};
    if (!email || !password)
      return res.status(400).json({ error: "missing_credentials" });
    const r = await pool.query("select * from users where email=$1", [email]);
    if (!r.rowCount)
      return res.status(401).json({ error: "invalid_credentials" });
    const user = r.rows[0];
    if (role && role !== user.role)
      return res.status(401).json({ error: "role_mismatch" });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "invalid_credentials" });
    const accessToken = signAccessToken(user);
    const refreshToken = signRefreshToken(user);
    await storeRefreshToken(user.id, refreshToken);
    res.json({
      accessToken,
      refreshToken,
      user: { id: user.id, name: user.name, role: user.role },
    });
  } catch (e) {
    next(e);
  }
});

app.post("/auth/refresh", async (req, res, next) => {
  try {
    const { refreshToken } = req.body || {};
    if (!refreshToken)
      return res.status(400).json({ error: "missing_refresh_token" });
    const payload = await verifyRefreshToken(refreshToken);
    if (!payload) return res.status(401).json({ error: "invalid_refresh" });
    const user = await getUserById(payload.sub);
    if (!user) return res.status(401).json({ error: "user_not_found" });
    const accessToken = signAccessToken(user);
    res.json({ accessToken });
  } catch (e) {
    next(e);
  }
});

app.post("/auth/logout", auth(), async (req, res, next) => {
  try {
    const { refreshToken } = req.body || {};
    if (refreshToken) {
      await pool.query(
        "update refresh_tokens set revoked=true where token=$1 and user_id=$2",
        [refreshToken, req.user.id]
      );
    }
    res.json({ success: true });
  } catch (e) {
    next(e);
  }
});

// Profile
app.get("/profile/me", auth(), async (req, res, next) => {
  try {
    const user = await getUserById(req.user.id);
    res.json(user);
  } catch (e) {
    next(e);
  }
});

app.put("/profile/me", auth(), async (req, res, next) => {
  try {
    const { name, phone, address, meta, orgName, contactPerson } =
      req.body || {};
    await pool.query(
      `update users set
         name = coalesce($2,name),
         phone = coalesce($3,phone),
         address = coalesce($4,address),
         meta = coalesce($5,meta),
         org_name = coalesce($6,org_name),
         contact_person = coalesce($7,contact_person)
       where id=$1`,
      [req.user.id, name, phone, address, meta, orgName, contactPerson]
    );
    const updated = await getUserById(req.user.id);
    res.json(updated);
  } catch (e) {
    next(e);
  }
});

app.get("/users/:id", auth(), async (req, res, next) => {
  try {
    const user = await getUserById(req.params.id);
    if (!user) return res.status(404).json({ error: "not_found" });
    if (req.user.role === "admin" || req.user.id === user.id)
      return res.json(user);
    // redacted
    res.json({ id: user.id, name: user.name, role: user.role });
  } catch (e) {
    next(e);
  }
});

// Trusted contacts
app.get(
  "/profile/me/trusted-contacts",
  auth(),
  requireRole("user"),
  async (req, res, next) => {
    try {
      const r = await pool.query(
        "select * from trusted_contacts where user_id=$1 order by created_at desc",
        [req.user.id]
      );
      res.json(r.rows);
    } catch (e) {
      next(e);
    }
  }
);
app.post(
  "/profile/me/trusted-contacts",
  auth(),
  requireRole("user"),
  async (req, res, next) => {
    try {
      const { name, relation, phone, email, guardianId } = req.body || {};
      if (!name) return res.status(400).json({ error: "name_required" });
      const id = uuid();
      await pool.query(
        "insert into trusted_contacts(id,user_id,name,relation,phone,email,guardian_id) values($1,$2,$3,$4,$5,$6,$7)",
        [id, req.user.id, name, relation, phone, email, guardianId]
      );
      res.status(201).json({ id });
    } catch (e) {
      next(e);
    }
  }
);
app.delete(
  "/profile/me/trusted-contacts/:contactId",
  auth(),
  requireRole("user"),
  async (req, res, next) => {
    try {
      await pool.query(
        "delete from trusted_contacts where id=$1 and user_id=$2",
        [req.params.contactId, req.user.id]
      );
      res.json({ success: true });
    } catch (e) {
      next(e);
    }
  }
);

// Guardian tracking
app.post(
  "/guardian/track-request",
  auth(),
  requireRole("guardian"),
  async (req, res, next) => {
    try {
      const { targetUserId, message } = req.body || {};
      if (!targetUserId)
        return res.status(400).json({ error: "target_required" });
      const id = uuid();
      await pool.query(
        "insert into track_requests(id,guardian_id,target_user_id,message) values($1,$2,$3,$4)",
        [id, req.user.id, targetUserId, message]
      );
      // TODO: notification dispatch
      res.status(201).json({ id, status: "pending" });
    } catch (e) {
      next(e);
    }
  }
);
app.get(
  "/guardian/requests",
  auth(),
  requireRole("guardian"),
  async (req, res, next) => {
    try {
      const r = await pool.query(
        "select * from track_requests where guardian_id=$1 order by created_at desc",
        [req.user.id]
      );
      res.json(r.rows);
    } catch (e) {
      next(e);
    }
  }
);
app.post(
  "/user/track-request/:requestId/respond",
  auth(),
  requireRole("user"),
  async (req, res, next) => {
    try {
      const { approved } = req.body || {};
      const requestId = req.params.requestId;
      const r = await pool.query("select * from track_requests where id=$1", [
        requestId,
      ]);
      if (!r.rowCount) return res.status(404).json({ error: "not_found" });
      const reqRow = r.rows[0];
      if (reqRow.target_user_id !== req.user.id)
        return res.status(403).json({ error: "forbidden" });
      const status = approved ? "approved" : "denied";
      await pool.query("update track_requests set status=$2 where id=$1", [
        requestId,
        status,
      ]);
      if (approved) {
        await pool.query(
          "insert into guardian_access(guardian_id,user_id) values($1,$2) on conflict do nothing",
          [reqRow.guardian_id, reqRow.target_user_id]
        );
      }
      // TODO: notify guardian
      res.json({ status });
    } catch (e) {
      next(e);
    }
  }
);
app.post(
  "/guardian/:guardianId/revoke/:userId",
  auth(),
  async (req, res, next) => {
    try {
      const { guardianId, userId } = req.params;
      if (req.user.role === "guardian" && req.user.id !== guardianId)
        return res.status(403).json({ error: "forbidden" });
      if (req.user.role === "user" && req.user.id !== userId)
        return res.status(403).json({ error: "forbidden" });
      await pool.query(
        "delete from guardian_access where guardian_id=$1 and user_id=$2",
        [guardianId, userId]
      );
      res.json({ success: true });
    } catch (e) {
      next(e);
    }
  }
);

// Locations
app.post("/locations", auth(), requireRole("user"), async (req, res, next) => {
  try {
    const { lat, lng, accuracy, timestamp } = req.body || {};
    if (typeof lat !== "number" || typeof lng !== "number")
      return res.status(400).json({ error: "invalid_coords" });
    await pool.query(
      "insert into locations(user_id,lat,lng,accuracy,recorded_at) values($1,$2,$3,$4,coalesce($5,now()))",
      [req.user.id, lat, lng, accuracy, timestamp ? new Date(timestamp) : null]
    );
    res.status(201).json({ success: true });
  } catch (e) {
    next(e);
  }
});

app.get("/locations/latest/:userId", auth(), async (req, res, next) => {
  try {
    const allowed = await canViewLocation(
      req.user.id,
      req.user.role,
      req.params.userId
    );
    if (!allowed) return res.status(403).json({ error: "forbidden" });
    const r = await pool.query(
      "select lat,lng,accuracy,recorded_at from locations where user_id=$1 order by recorded_at desc limit 1",
      [req.params.userId]
    );
    if (!r.rowCount) return res.status(404).json({ error: "not_found" });
    res.json(r.rows[0]);
  } catch (e) {
    next(e);
  }
});

app.get("/locations/history/:userId", auth(), async (req, res, next) => {
  try {
    const { from, to, limit = 100 } = req.query;
    const allowed = await canViewLocation(
      req.user.id,
      req.user.role,
      req.params.userId
    );
    if (!allowed) return res.status(403).json({ error: "forbidden" });
    const params = [req.params.userId];
    let where = "user_id=$1";
    if (from) {
      params.push(new Date(from));
      where += ` and recorded_at >= $${params.length}`;
    }
    if (to) {
      params.push(new Date(to));
      where += ` and recorded_at <= $${params.length}`;
    }
    params.push(Math.min(parseInt(limit, 10) || 100, 1000));
    const r = await pool.query(
      `select lat,lng,accuracy,recorded_at
       from locations
       where ${where}
       order by recorded_at desc
       limit $${params.length}`,
      params
    );
    res.json(r.rows);
  } catch (e) {
    next(e);
  }
});

// SOS
app.post("/sos", auth(), requireRole("user"), async (req, res, next) => {
  try {
    const { lat, lng, note, emergencyType } = req.body || {};
    const id = uuid();
    await pool.query(
      "insert into sos(id,user_id,lat,lng,note,emergency_type) values($1,$2,$3,$4,$5,$6)",
      [id, req.user.id, lat, lng, note, emergencyType]
    );
    // TODO: notifications to guardians/trusted contacts/NGOs
    res.status(201).json({ id, active: true });
  } catch (e) {
    next(e);
  }
});

app.get("/sos/:id", auth(), async (req, res, next) => {
  try {
    // TODO: authorization refinement
    const r = await pool.query("select * from sos where id=$1", [
      req.params.id,
    ]);
    if (!r.rowCount) return res.status(404).json({ error: "not_found" });
    if (
      req.user.role !== "admin" &&
      req.user.id !== r.rows[0].user_id &&
      req.user.role !== "guardian" &&
      req.user.role !== "ngo"
    )
      return res.status(403).json({ error: "forbidden" });
    res.json(r.rows[0]);
  } catch (e) {
    next(e);
  }
});

app.post("/sos/:id/resolve", auth(), async (req, res, next) => {
  try {
    const r = await pool.query("select * from sos where id=$1", [
      req.params.id,
    ]);
    if (!r.rowCount) return res.status(404).json({ error: "not_found" });
    const record = r.rows[0];
    if (
      req.user.role !== "ngo" &&
      req.user.id !== record.user_id &&
      req.user.role !== "admin"
    )
      return res.status(403).json({ error: "forbidden" });
    if (!record.active) return res.json({ alreadyResolved: true });
    await pool.query(
      "update sos set active=false, resolved_at=now() where id=$1",
      [req.params.id]
    );
    res.json({ resolved: true });
  } catch (e) {
    next(e);
  }
});

// NGO routes (registration uses sign-up). Assistance requests placeholder.
app.get(
  "/ngos/:id/assistance-requests",
  auth(),
  requireRole("ngo"),
  async (_req, res) => {
    // TODO: join SOS assigned to NGO
    res.json({ items: [], todo: true });
  }
);
app.post(
  "/ngos/:id/assign-doctor",
  auth(),
  requireRole("ngo"),
  async (req, res, next) => {
    try {
      if (req.user.id !== req.params.id)
        return res.status(403).json({ error: "forbidden" });
      const { name, phone, specialty, lat, lng } = req.body || {};
      if (!name) return res.status(400).json({ error: "missing_name" });
      const id = uuid();
      await pool.query(
        "insert into doctors(id,ngo_id,name,phone,specialty,lat,lng) values($1,$2,$3,$4,$5,$6,$7)",
        [id, req.user.id, name, phone, specialty, lat, lng]
      );
      res.status(201).json({ id });
    } catch (e) {
      next(e);
    }
  }
);

// Doctors
app.post("/doctors", auth(), requireRole("ngo"), async (req, res, next) => {
  try {
    const { name, phone, specialty, lat, lng } = req.body || {};
    if (!name) return res.status(400).json({ error: "missing_name" });
    const id = uuid();
    await pool.query(
      "insert into doctors(id,ngo_id,name,phone,specialty,lat,lng) values($1,$2,$3,$4,$5,$6,$7)",
      [id, req.user.id, name, phone, specialty, lat, lng]
    );
    res.status(201).json({ id });
  } catch (e) {
    next(e);
  }
});

app.get("/doctors/nearby", async (req, res, next) => {
  try {
    const { lat, lng, radius = 10 } = req.query;
    if (!lat || !lng) return res.status(400).json({ error: "missing_coords" });
    // Simple bounding box (not precise great-circle)
    const r = parseFloat(radius);
    const la = parseFloat(lat);
    const lo = parseFloat(lng);
    const rRows = await pool.query(
      `select id,name,phone,specialty,lat,lng,
        sqrt( (lat-$1)*(lat-$1) + (lng-$2)*(lng-$2) ) as approx_distance
       from doctors
       where lat between $1-0.2 and $1+0.2
         and lng between $2-0.2 and $2+0.2
       order by approx_distance asc
       limit 50`,
      [la, lo]
    );
    res.json(rRows.rows.filter((x) => x.approx_distance <= r / 111)); // crude conversion
  } catch (e) {
    next(e);
  }
});

// Admin & stats
app.get(
  "/admin/users",
  auth(),
  requireRole("admin"),
  async (_req, res, next) => {
    try {
      const r = await pool.query(
        "select id,name,email,role,created_at from users order by created_at desc limit 500"
      );
      res.json(r.rows);
    } catch (e) {
      next(e);
    }
  }
);

app.patch(
  "/admin/users/:id/verify",
  auth(),
  requireRole("admin"),
  async (req, res) => {
    // TODO: Mark NGO verified; add column in future migration.
    res.json({ todo: true });
  }
);

app.get("/stats", auth(), async (req, res, next) => {
  try {
    if (!["admin", "ngo"].includes(req.user.role))
      return res.status(403).json({ error: "forbidden" });
    const [u, s, l] = await Promise.all([
      pool.query("select count(*) from users"),
      pool.query("select count(*) from sos where active=true"),
      pool.query(
        "select count(*) from locations where recorded_at > now() - interval '1 day'"
      ),
    ]);
    res.json({
      users: parseInt(u.rows[0].count, 10),
      activeSOS: parseInt(s.rows[0].count, 10),
      locationsLast24h: parseInt(l.rows[0].count, 10),
    });
  } catch (e) {
    next(e);
  }
});

// 404
app.use((_req, res) => res.status(404).json({ error: "not_found" }));

// Error handler
app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: "server_error" });
});

const port = process.env.PORT || 3000;
const server = app.listen(port, () => {
  console.log(`Nirbhaya backend listening on :${port}`);
});
// Export for tests
module.exports = { app, pool, server };
