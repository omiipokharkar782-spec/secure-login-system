# Secure Login System

A beginner-friendly login application built with Node.js, Express, SQLite and bcryptjs.

## Features
- User registration and login
- Password hashing with bcrypt (12 salt rounds)
- Server-side input validation
- Parameterized SQLite queries (helps prevent SQL injection)
- Session-based authentication with session ID regeneration after login
- Logout and session destruction
- SQLite-backed session storage
- HTTP-only, SameSite cookies; Secure cookies in production
- Helmet security headers
- Login and registration rate limiting
- Secrets loaded from `.env`
- Generic login error message and generic server error page

## Requirements
- Node.js 18 or later
- npm

## Setup (Windows / macOS / Linux)
1. Extract the ZIP file.
2. Open a terminal in the `secure-login-system` folder.
3. Install packages:
   ```bash
   npm install
   ```
4. Create your environment file:
   - Windows CMD: `copy .env.example .env`
   - PowerShell: `Copy-Item .env.example .env`
   - macOS/Linux: `cp .env.example .env`
5. Open `.env` and replace `SESSION_SECRET` with a long random value (32+ characters).
6. Start the app:
   ```bash
   npm start
   ```
7. Open `http://localhost:3000` in your browser.
8. Register a new user, log in, test the dashboard, and log out.

## Test checklist
- Register with a valid name, email and password (minimum 10 characters).
- Try an invalid email and a short password; validation should reject them.
- Log in with the correct password; dashboard should appear.
- Log in with a wrong password; access should be denied with a generic message.
- Open `/dashboard` after logging out; app should redirect to `/login`.
- Repeated login attempts are rate-limited.

## Database
The app creates `users.db` automatically. User passwords are stored as bcrypt hashes, never as plain text. SQL statements use placeholders (`?`) and parameter arrays.

## Important production hardening
This is an educational mini-project, not a complete production identity platform. Before public deployment:
- Use HTTPS and set `NODE_ENV=production`.
- Use a strong unique `SESSION_SECRET`; keep `.env` out of GitHub.
- Add CSRF protection to state-changing forms, email verification, password reset and account lockout/monitoring.
- Consider Argon2id for password hashing and stronger password policy / breached-password checks.
- Configure a persistent session store such as Redis or a managed database for multi-instance deployments.
- Add database backups, log monitoring, dependency scanning and security tests.
- Do not log passwords, session IDs, tokens or secrets.

## GitHub upload
```bash
git init
git add .
git commit -m "Build secure login system"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/secure-login-system.git
git push -u origin main
```
Do not upload `.env`, `node_modules`, `users.db` or `sessions.sqlite`; `.gitignore` excludes them.
