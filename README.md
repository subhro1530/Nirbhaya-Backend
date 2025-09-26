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

### 2. Auth Flow (Updated single token)

Sign in:

```
resp=$(curl -s -X POST $BASE/auth/sign-in -H "Content-Type: application/json" -d '{"email":"alice@example.com","password":"Pass123!"}')
export USER_TOKEN=$(echo $resp | jq -r '.accessToken')
curl -H "Authorization: Bearer $USER_TOKEN" $BASE/profile/me
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

### Newly Added Endpoints (Tracking Enhancements)

### 1. Resolve User By Email

GET /users/lookup/email/:email  
Purpose: Convert a known email to internal user id (guardian / any authenticated role).

Curl:

```
curl -H "Authorization: Bearer $GUARDIAN_TOKEN" \
  "$BASE/users/lookup/email/alice@example.com"
```

Demo response:

```json
{
  "id": "5e4c2c6b-3b1d-4a54-9d8f-2f0b6b2b9f11",
  "name": "Alice",
  "email": "alice@example.com",
  "role": "user"
}
```

### 2. Create Track Request (Now supports targetEmail)

POST /guardian/track-request  
Body accepts either targetUserId or targetEmail.

Curl with email (preferred – no need to know userId):

```
curl -X POST $BASE/guardian/track-request \
  -H "Authorization: Bearer $GUARDIAN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"targetEmail":"alice@example.com"}'
```

Curl with direct user id:

```
curl -X POST $BASE/guardian/track-request \
  -H "Authorization: Bearer $GUARDIAN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"targetUserId":"5e4c2c6b-3b1d-4a54-9d8f-2f0b6b2b9f11"}'
```

Demo response:

```json
{
  "id": "9c55b1b4-0c6d-4c2a-9e5f-1a2bb4c9d120",
  "status": "pending"
}
```

Errors:

- 404 target_not_found
- 409 already_pending
- 400 cannot_request_self / provide targetUserId or targetEmail

### 3. List Incoming Track Requests (User dashboard)

GET /user/track-requests (user role)  
Shows all requests (pending, approved, denied) with guardian info.

Curl:

```
curl -H "Authorization: Bearer $USER_TOKEN" $BASE/user/track-requests
```

Demo response:

```json
[
  {
    "id": "9c55b1b4-0c6d-4c2a-9e5f-1a2bb4c9d120",
    "status": "pending",
    "created_at": "2025-09-25T21:05:10.123Z",
    "guardian": {
      "id": "c8422b76-8e6f-4d83-915d-0e4c1fb0d901",
      "name": "Guardian Gabe",
      "email": "gabe@example.com"
    }
  },
  {
    "id": "2fe18f5d-7a31-4fa9-85a9-6b5dd0f5b7b2",
    "status": "approved",
    "created_at": "2025-09-24T14:11:37.900Z",
    "guardian": {
      "id": "c8422b76-8e6f-4d83-915d-0e4c1fb0d901",
      "name": "Guardian Gabe",
      "email": "gabe@example.com"
    }
  }
]
```

### 4. Approve / Deny Track Request (stores linkage)

POST /user/track-request/:requestId/respond  
Body: {"approved": true} or {"approved": false}

Curl approve:

```
curl -X POST $BASE/user/track-request/9c55b1b4-0c6d-4c2a-9e5f-1a2bb4c9d120/respond \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"approved":true}'
```

Demo response:

```json
{ "status": "approved" }
```

On approval guardian_access row includes request_id.

### 5. Extended /profile/me (Users Only: trackRequests embedded)

GET /profile/me

Curl:

```
curl -H "Authorization: Bearer $USER_TOKEN" $BASE/profile/me
```

Demo response (truncated):

```json
{
  "id": "5e4c2c6b-3b1d-4a54-9d8f-2f0b6b2b9f11",
  "name": "Alice",
  "email": "alice@example.com",
  "role": "user",
  "trackRequests": [
    {
      "id": "9c55b1b4-0c6d-4c2a-9e5f-1a2bb4c9d120",
      "status": "pending",
      "created_at": "2025-09-25T21:05:10.123Z",
      "guardian": {
        "id": "c8422b76-8e6f-4d83-915d-0e4c1fb0d901",
        "name": "Guardian Gabe",
        "email": "gabe@example.com"
      }
    }
  ]
}
```

### Summary of Changes

- Added GET /users/lookup/email/:email
- Enhanced POST /guardian/track-request to accept targetEmail
- Added GET /user/track-requests
- Approval now links request -> guardian_access (request_id column)
- /profile/me returns trackRequests for users
- Single 30‑day token (no refresh flow)

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

### Guardian Tracking Rule (Updated)

A guardian can create only ONE track request per user (lifetime). If a request already exists (pending / approved / denied), attempting another returns:

```
409 {
  "error":"request_already_exists",
  "request":{"id":"<id>","status":"approved"}
}
```

- Approval now links request -> guardian_access (request_id column)
- /profile/me returns trackRequests for users
- Single 30‑day token (no refresh flow)

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

### Guardian Tracking Rule (Updated)

A guardian can create only ONE track request per user (lifetime). If a request already exists (pending / approved / denied), attempting another returns:

```
409 {
  "error":"request_already_exists",
  "request":{"id":"<id>","status":"approved"}
}
```
