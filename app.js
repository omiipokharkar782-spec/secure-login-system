require('dotenv').config();
const path = require('path');
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');
const { body, validationResult } = require('express-validator');

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const isProduction = process.env.NODE_ENV === 'production';

if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  console.error('SESSION_SECRET is missing or too short. Copy .env.example to .env and set a random secret of 32+ characters.');
  process.exit(1);
}

// SQLite database and promise helpers.
const db = new sqlite3.Database(path.join(__dirname, 'users.db'));
const run = (sql, params = []) => new Promise((resolve, reject) => {
  db.run(sql, params, function (err) { if (err) reject(err); else resolve(this); });
});
const get = (sql, params = []) => new Promise((resolve, reject) => {
  db.get(sql, params, (err, row) => { if (err) reject(err); else resolve(row); });
});

const schemaReady = run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
)`);

if (isProduction) app.set('trust proxy', 1);
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(helmet());
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: __dirname }),
  name: 'secure_login_sid',
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, secure: isProduction, sameSite: 'lax', maxAge: 1000 * 60 * 30 }
}));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: 'Too many attempts. Please wait 15 minutes and try again.'
});
const registerLimiter = rateLimit({ windowMs: 60 * 60 * 1000, limit: 5, standardHeaders: 'draft-7', legacyHeaders: false });

function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}
function showErrors(req, res, view, extra = {}) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).render(view, { errors: errors.array(), ...extra });
  return null;
}

app.get('/', (req, res) => res.redirect(req.session.user ? '/dashboard' : '/login'));
app.get('/register', (req, res) => res.render('register', { errors: [] }));
app.post('/register', registerLimiter,
  body('name').trim().isLength({ min: 2, max: 60 }).withMessage('Name must be 2–60 characters.'),
  body('email').trim().isEmail().normalizeEmail().withMessage('Enter a valid email address.'),
  body('password').isLength({ min: 10, max: 72 }).withMessage('Password must be 10–72 characters.'),
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).render('register', { errors: errors.array() });
    try {
      const name = req.body.name;
      const email = req.body.email.toLowerCase();
      const existing = await get('SELECT id FROM users WHERE email = ?', [email]);
      if (existing) return res.status(409).render('register', { errors: [{ msg: 'An account with this email already exists.' }] });
      const passwordHash = await bcrypt.hash(req.body.password, 12);
      await run('INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)', [name, email, passwordHash]);
      return res.redirect('/login?registered=1');
    } catch (err) { next(err); }
  }
);

app.get('/login', (req, res) => res.render('login', { errors: [], registered: req.query.registered === '1' }));
app.post('/login', loginLimiter,
  body('email').trim().isEmail().normalizeEmail().withMessage('Enter a valid email address.'),
  body('password').notEmpty().withMessage('Password is required.'),
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).render('login', { errors: errors.array(), registered: false });
    try {
      const email = req.body.email.toLowerCase();
      const user = await get('SELECT id, name, email, password_hash FROM users WHERE email = ?', [email]);
      // Same message for unknown email and wrong password to reduce account enumeration.
      const valid = user ? await bcrypt.compare(req.body.password, user.password_hash) : false;
      if (!valid) return res.status(401).render('login', { errors: [{ msg: 'Invalid email or password.' }], registered: false });
      // Regenerate session ID after authentication to reduce session-fixation risk.
      req.session.regenerate((err) => {
        if (err) return next(err);
        req.session.user = { id: user.id, name: user.name, email: user.email };
        req.session.save((saveErr) => saveErr ? next(saveErr) : res.redirect('/dashboard'));
      });
    } catch (err) { next(err); }
  }
);

app.get('/dashboard', requireAuth, (req, res) => res.render('dashboard', { user: req.session.user }));
app.post('/logout', requireAuth, (req, res, next) => {
  req.session.destroy((err) => {
    if (err) return next(err);
    res.clearCookie('secure_login_sid', { httpOnly: true, secure: isProduction, sameSite: 'lax' });
    res.redirect('/login');
  });
});

app.use((err, req, res, next) => {
  console.error(err); // In production, send logs to a protected log service; never log passwords or secrets.
  res.status(500).send('Something went wrong. Please try again later.');
});

schemaReady
  .then(() => app.listen(PORT, () => console.log(`Secure Login System running at http://localhost:${PORT}`)))
  .catch((err) => { console.error('Could not initialize database:', err); process.exit(1); });
