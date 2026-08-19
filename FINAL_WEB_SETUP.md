# Final Web Version — Customer / Admin / Database

## Included

### Customer
- Login
- Upload Source PDF only
- Source PDF parsing
- V59 PDF generation/layout
- Default background is automatic
- Balance display
- Per-generation charge
- Download
- Persistent generation history

### Admin
- Admin login
- Customer creation
- Customer balance credit/debit
- PDF price
- Upload and set one Default Background
- Customer list
- Dashboard

### Database
When `DATABASE_URL` is set, the application uses CockroachDB/PostgreSQL through SQLAlchemy.
Without `DATABASE_URL`, local SQLite (`data/web.sqlite3`) is used for testing.

### Persistent data
Customer accounts, balances, pricing, background image and generation records are stored in the web database.
Generated PDF data is stored with the generation record so history downloads can survive a Render restart. This increases database storage usage as PDF history grows.

## Required Render environment variables

Set these in Render:

DATABASE_URL = CockroachDB connection string
SESSION_SECRET = long random secret
ADMIN_EMAIL = your admin email
ADMIN_PASSWORD = strong admin password

Do not commit real secrets to GitHub.

## Render deployment

The included Dockerfile installs Chromium because the existing V59 PDF engine uses headless Chromium to render the PDF.

Render:
- Service type: Web Service
- Runtime: Docker
- Plan: Free

The service listens on `$PORT`.

## Customer flow

Admin sets Default Background once.
Customer logs in -> uploads Source PDF -> system automatically uses the current Default Background -> PDF is generated -> balance is charged -> PDF is stored in history.

Customers do not upload/change the Background.

## Important

This package is the application layer. Payment gateway, email/SMS verification and production-grade object storage are not included yet.

## First login

The admin account is created on first database initialization from:
- `ADMIN_EMAIL`
- `ADMIN_PASSWORD`

Set both in Render before the first deploy. Do not use the development defaults in a public deployment.

Customers cannot choose or upload a background. Only the admin can set the single active default background.
