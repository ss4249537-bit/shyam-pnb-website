# Publish checklist

## Recommended production layout
- PostgreSQL is private and not directly exposed to the internet.
- The Node server is public over HTTPS.
- The same Node server serves the React build and `/api`.
- `server/.env` is created only on the server and is never uploaded as a public/static file.

## Required server environment variables
Copy `server/.env.example` to a private `server/.env` and fill in:
- DATABASE_URL
- SESSION_SECRET
- CSRF_SECRET
- SENSITIVE_DATA_KEY
- APP_ORIGIN
- COOKIE_SECURE=true
- ADMIN_USERNAME
- ADMIN_PASSWORD
- ADMIN_DAILY_PIN
- PUBLIC_CONTACT

The Admin ID/password/PIN are not present in the React build.

## First start
1. Create the PostgreSQL database.
2. Run `server/sql/schema.sql` once.
3. Build the client: `cd client && npm install && npm run build`.
4. Build the server: `cd server && npm install && npm run build`.
5. Start: `npm start` from `server/`.
6. Open the HTTPS domain. Home should load; Admin is available only through the Admin Login menu and server authentication.

## Paytm subscription verification
The QR file is already included in the client build as `/paytm-qr.png`.
- Operator pays the exact amount.
- Operator submits UTR + payment date/time.
- Admin checks the Paytm Business account manually.
- Admin approves or rejects from Payments.
- Until approval, paid tools remain locked.

## Docker option
- Set `POSTGRES_PASSWORD` in a private Compose environment file.
- Create `server/.env` from `server/.env.example` with the same database password in `DATABASE_URL` plus the private Admin/secrets.
- Run the schema against the `db` service once, then `docker compose up -d --build`.
- Put HTTPS in front of port 4000 using your hosting provider/reverse proxy.
