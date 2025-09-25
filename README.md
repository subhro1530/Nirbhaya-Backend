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

## API Testing (curl examples)

Set a base URL (local):

```
export BASE=http://localhost:3000
```

(Windows PowerShell: `$env:BASE="http://localhost:3000"`)

### 1. Health / Version

```
curl $BASE/health
curl $BASE/version
```

### 2. Auth Flow

Sign up (user / guardian / ngo):

```
curl -X POST $BASE/auth/sign-up -H "Content-Type: application/json" -d '{"name":"Alice","email":"alice@example.com","password":"Pass123!","role":"user"}'
curl -X POST $BASE/auth/sign-up -H "Content-Type: application/json" -d '{"name":"Gabe","email":"gabe@example.com","password":"Pass123!","role":"guardian"}'
curl -X POST $BASE/auth/sign-up -H "Content-Type: application/json" -d '{"name":"Helping Org","email":"ngo@example.com","password":"Pass123!","role":"ngo"}'
```

Sign in (store tokens):

```
resp=$(curl -s -X POST $BASE/auth/sign-in -H "Content-Type: application/json" -d '{"email":"alice@example.com","password":"Pass123!"}')
export USER_ACCESS=$(echo $resp | jq -r '.accessToken')
export USER_REFRESH=$(echo $resp | jq -r '.refreshToken')

resp=$(curl -s -X POST $BASE/auth/sign-in -H "Content-Type: application/json" -d '{"email":"gabe@example.com","password":"Pass123!"}')
export GUARDIAN_ACCESS=$(echo $resp | jq -r '.accessToken')

resp=$(curl -s -X POST $BASE/auth/sign-in -H "Content-Type: application/json" -d '{"email":"ngo@example.com","password":"Pass123!"}')
export NGO_ACCESS=$(echo $resp | jq -r '.accessToken')
```

Refresh:

```
curl -X POST $BASE/auth/refresh -H "Content-Type: application/json" -d "{\"refreshToken\":\"$USER_REFRESH\"}"
```

Logout:

```
curl -X POST $BASE/auth/logout -H "Authorization: Bearer $USER_ACCESS" -H "Content-Type: application/json" -d "{\"refreshToken\":\"$USER_REFRESH\"}"
```

### 3. Profile

```
curl -H "Authorization: Bearer $USER_ACCESS" $BASE/profile/me
curl -X PUT $BASE/profile/me -H "Authorization: Bearer $USER_ACCESS" -H "Content-Type: application/json" -d '{"phone":"+1999888777"}'
```

Get another user (will redact unless self/admin):

```
curl -H "Authorization: Bearer $USER_ACCESS" $BASE/users/<userId>
```

### 4. Trusted Contacts (user only)

```
curl -H "Authorization: Bearer $USER_ACCESS" $BASE/profile/me/trusted-contacts
curl -X POST $BASE/profile/me/trusted-contacts -H "Authorization: Bearer $USER_ACCESS" -H "Content-Type: application/json" -d '{"name":"Mom","relation":"mother","phone":"+111"}'
curl -X DELETE $BASE/profile/me/trusted-contacts/<contactId> -H "Authorization: Bearer $USER_ACCESS"
```

### 5. Guardian Tracking

Guardian requests access to user (need target userId from signup response):

```
curl -X POST $BASE/guardian/track-request -H "Authorization: Bearer $GUARDIAN_ACCESS" -H "Content-Type: application/json" -d '{"targetUserId":"<userId>","message":"Safety monitoring"}'
```

Guardian views requests:

```
curl -H "Authorization: Bearer $GUARDIAN_ACCESS" $BASE/guardian/requests
```

User responds (requestId from previous):

```
curl -X POST $BASE/user/track-request/<requestId>/respond -H "Authorization: Bearer $USER_ACCESS" -H "Content-Type: application/json" -d '{"approved":true}'
```

Revoke:

```
curl -X POST $BASE/guardian/<guardianId>/revoke/<userId> -H "Authorization: Bearer $USER_ACCESS"
```

### 6. Locations (user pushes, guardian reads after approval)

Send location:

```
curl -X POST $BASE/locations -H "Authorization: Bearer $USER_ACCESS" -H "Content-Type: application/json" -d '{"lat":12.9716,"lng":77.5946,"accuracy":15}'
```

Latest (user self):

```
curl -H "Authorization: Bearer $USER_ACCESS" $BASE/locations/latest/<userId>
```

Latest (guardian after approval):

```
curl -H "Authorization: Bearer $GUARDIAN_ACCESS" $BASE/locations/latest/<userId>
```

History:

```
curl -H "Authorization: Bearer $USER_ACCESS" "$BASE/locations/history/<userId>?limit=50&from=2024-01-01"
```

### 7. SOS

Create:

```
resp=$(curl -s -X POST $BASE/sos -H "Authorization: Bearer $USER_ACCESS" -H "Content-Type: application/json" -d '{"lat":12.9,"lng":77.5,"note":"Help","emergencyType":"distress"}')
export SOS_ID=$(echo $resp | jq -r '.id')
```

Get:

```
curl -H "Authorization: Bearer $USER_ACCESS" $BASE/sos/$SOS_ID
```

Resolve (user or NGO):

```
curl -X POST $BASE/sos/$SOS_ID/resolve -H "Authorization: Bearer $USER_ACCESS"
```

### 8. NGO / Doctors

Assign a doctor (ngoId = NGO user id):

```
curl -X POST $BASE/ngos/<ngoId>/assign-doctor -H "Authorization: Bearer $NGO_ACCESS" -H "Content-Type: application/json" -d '{"name":"Dr Joy","phone":"+222","specialty":"counselor","lat":12.95,"lng":77.60}'
```

Add doctor (alternate endpoint):

```
curl -X POST $BASE/doctors -H "Authorization: Bearer $NGO_ACCESS" -H "Content-Type: application/json" -d '{"name":"Dr Aid","specialty":"trauma","lat":12.95,"lng":77.60}'
```

Nearby doctors:

```
curl "$BASE/doctors/nearby?lat=12.95&lng=77.60&radius=5"
```

Assistance requests placeholder:

```
curl -H "Authorization: Bearer $NGO_ACCESS" $BASE/ngos/<ngoId>/assistance-requests
```

### 9. Admin (requires seeded admin sign-in)

Sign in admin (email/password from env):

```
resp=$(curl -s -X POST $BASE/auth/sign-in -H "Content-Type: application/json" -d '{"email":"admin@example.com","password":"ChangeMe123!"}')
export ADMIN_ACCESS=$(echo $resp | jq -r '.accessToken')
```

List users:

```
curl -H "Authorization: Bearer $ADMIN_ACCESS" $BASE/admin/users
```

Verify (placeholder):

```
curl -X PATCH $BASE/admin/users/<ngoUserId>/verify -H "Authorization: Bearer $ADMIN_ACCESS" -H "Content-Type: application/json" -d '{}'
```

Stats:

```
curl -H "Authorization: Bearer $ADMIN_ACCESS" $BASE/stats
```

### 10. Utility

```
curl $BASE/health
curl $BASE/version
```

### Notes

- Replace <userId>, <guardianId>, <ngoId>, <requestId>, <contactId> with real IDs from prior responses.
- jq is used for parsing JSON (install if missing) or inspect raw output.
- 401 = invalid/missing token; 403 = role/authorization denied.
- Re-run location POST several times before history queries.

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
