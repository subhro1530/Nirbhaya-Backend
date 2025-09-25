# Nirbhaya Backend

Express + PostgreSQL (Neon) backend scaffold deployable on Render.

## Features (scaffolded)

- Authentication (JWT access + refresh)
- Role-based users: user, guardian, ngo, admin
- Profile CRUD
- Trusted contacts CRUD
- Guardian tracking requests + approvals
- Location ingestion & retrieval (latest + history)
- SOS creation & resolution
- NGO + doctor registry (basic)
- Admin user listing & verification placeholder
- Basic stats, health, version endpoints

## Tech

- Node.js 18+
- Express
- PostgreSQL (Neon recommended)
- JWT (access 15m, refresh 30d)
- bcrypt password hashing

## Environment Variables

PORT=3000
DATABASE_URL=postgres://user:pass@host/db
PGSSLMODE=require # for Neon (enables SSL)
JWT_SECRET=change_me_access
JWT_REFRESH_SECRET=change_me_refresh
SEED_ADMIN=true
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=ChangeMe123!.

## Quick Start

1. Copy `.env` template (see below) and fill secrets.
2. Run: `npm install`
3. Start: `npm start`
4. Watch console for:
   - PostgreSQL pool connected
   - Database schema ensured
5. Test: `curl http://localhost:3000/health`

## Example .env

```
PORT=3000
DATABASE_URL=postgresql://neondb_owner:******@ep-sweet-base-ad77nrjo-pooler.c-2.us-east-1.aws.neon.tech/neondb?sslmode=require
PGSSLMODE=require
JWT_SECRET=your_access_secret
JWT_REFRESH_SECRET=your_refresh_secret
SEED_ADMIN=true
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=ChangeMe123!
```

## Manual Table Check (optional)

`npm run psql` then:

```
\d users
\d locations
```

You should see all created automatically.

## Local Development

npm install
npm run dev

## Deployment (Render)

1. Create Neon DB, copy connection string.
2. New Web Service in Render: Build command `npm install`, Start command `npm start`.
3. Set environment variables (above).
4. Ensure PGSSLMODE=require for Neon SSL.

## Route Summary

Auth:
POST /auth/sign-up
POST /auth/sign-in
POST /auth/refresh
POST /auth/logout

Profile & Users:
GET /profile/me
PUT /profile/me
GET /users/:id

Trusted Contacts:
GET /profile/me/trusted-contacts
POST /profile/me/trusted-contacts
DELETE /profile/me/trusted-contacts/:contactId

Guardian Tracking:
POST /guardian/track-request
GET /guardian/requests
POST /user/track-request/:requestId/respond
POST /guardian/:guardianId/revoke/:userId

Locations:
POST /locations
GET /locations/latest/:userId
GET /locations/history/:userId?from=&to=&limit=

SOS:
POST /sos
GET /sos/:id
POST /sos/:id/resolve

NGO:
GET /ngos/:id/assistance-requests
POST /ngos/:id/assign-doctor

Doctors:
POST /doctors
GET /doctors/nearby?lat=&lng=&radius=

Admin & Stats:
GET /admin/users
PATCH /admin/users/:id/verify
GET /stats

Utility:
GET /health
GET /version

## Notes / TODO

- Add structured validation (express-validator / zod).
- Add NGO verification column.
- Implement notifications (email / push / SMS).
- Geospatial indexing (PostGIS) for accurate nearby queries.
- Rate limiting & audit logging.
- Revocation list cleanup job.
- Add migrations tool (e.g., node-pg-migrate).

## License

Proprietary / TBD
