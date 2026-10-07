# SHYAM PNB PRO — Publishable Full-Stack Version

This package is a full-stack React + Express + PostgreSQL application. It is designed for multiple independent Operators with one private owner Admin.

## Main flow
- Public Home opens in a normal browser.
- Login and Sign Up are separate pages; Admin Login is owner-only.
- Sign Up: Name + Mobile + Password + Confirm Password. New accounts are Operators.
- Free Calculator is always available on Home without login or subscription.
- Operator paid tools remain locked until the ₹1 payment is manually verified by Admin.
- After 30 days, ₹29 renewal is submitted through the same Paytm QR + UTR verification process.
- Payment is not treated as successful until Admin checks the Paytm Business account and Approves it.
- Duplicate UTR / Transaction ID is blocked.
- Admin has all tools free and can see all Operators; each Operator can see only their own records.

## Paytm QR
The supplied Paytm QR image is included at:
`client/public/paytm-qr.png`

Operator payment flow:
1. Open Subscription.
2. Choose ₹1 first month or ₹29 renewal when due.
3. Scan the Paytm Business QR and pay the exact amount.
4. Enter UTR / Transaction ID and payment date/time.
5. Submit for Admin verification.
6. Admin opens Payments, checks Paytm Business manually, then Approves or Rejects.

## Security
- Admin credentials, Admin PIN, database credentials and encryption key are server environment variables only.
- No private Admin password/PIN is embedded in client JavaScript.
- Passwords are Argon2id hashed.
- Session cookie is httpOnly and state-changing requests use CSRF protection.
- Sensitive Aadhaar is encrypted at rest; normal screens show masked values. Full Aadhaar reveal is Admin-only.
- Operator data is isolated server-side.
- Personal Operator backup can be downloaded even when paid tools are locked.
- Admin backup excludes password hashes.
- Audit log records important actions.

## Setup
1. Install PostgreSQL and create the application database.
2. Copy `server/.env.example` to `server/.env` and set real production values.
3. Run `server/sql/schema.sql` against the database.
4. In `client/`, run `npm install` then `npm run build`.
5. In `server/`, run `npm install` then `npm run build` and `npm start`.
6. The Express server serves `client/dist` in production, so the public Home opens from the same server and `/api` stays same-origin.

## Important production settings
- Use HTTPS and set `COOKIE_SECURE=true`.
- Generate long random `SESSION_SECRET` and `CSRF_SECRET` values.
- Generate a 64-character hexadecimal `SENSITIVE_DATA_KEY`.
- Keep `server/.env` private and never commit it.
- Use a private PostgreSQL connection and regular database backups.

## Central Admin updates
Supported website settings are stored in PostgreSQL. Admin changes made in Website Settings are therefore centrally available to the live application instead of requiring every Operator's data to be edited manually.
