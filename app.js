import express from 'express';
import session from 'express-session';
import bcrypt from 'bcryptjs';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();


app.use(helmet());

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));


app.use(express.urlencoded({ extended: false, limit: '10kb' }));

app.use((req, res, next) => {
  if (req.method === 'POST' && !req.is('application/x-www-form-urlencoded')) {
    return res.status(400).send('Bad Request: Invalid Content-Type');
  }
  next();
});

const SESSION_SECRET = process.env.SESSION_SECRET || 'super-secret-key-pr6';
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { 
    httpOnly: true, 
    secure: process.env.NODE_ENV === 'production',
    maxAge: 3600000 
  }
}));

const users = [];

app.use((req, res, next) => {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }

  if (req.method === 'POST') {
    const clientToken = req.body._csrf;
    if (!clientToken || clientToken !== req.session.csrfToken) {
      return res.status(403).render('403', { message: 'Недійсний CSRF-токен або доступ заборонено.' });
    }
  }
  next();
});

const normalizeUsername = (req, res, next) => {
  if (req.body && req.body.username && typeof req.body.username === 'string') {
    req.body.username = req.body.username.trim().toLowerCase();
  }
  next();
};


const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  handler: (req, res) => {
    res.status(429).render('429');
  }
});



app.get('/', (req, res) => {
  res.redirect('/login');
});


app.get('/register', (req, res) => {
  res.render('register', { error: null, csrfToken: req.session.csrfToken });
});


app.post('/register', normalizeUsername, async (req, res) => {
  const { username, password } = req.body;

  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).render('register', { 
      error: 'Некоректний тип даних.', 
      csrfToken: req.session.csrfToken 
    });
  }


  if (username.length < 3 || username.length > 30) {
    return res.status(400).render('register', { 
      error: 'Username повинен містити від 3 до 30 символів.', 
      csrfToken: req.session.csrfToken 
    });
  }

  if (password.length < 8) {
    return res.status(400).render('register', { 
      error: 'Пароль повинен містити не менше 8 символів.', 
      csrfToken: req.session.csrfToken 
    });
  }

  const existingUser = users.find(u => u.username === username);
  if (existingUser) {
    return res.status(400).render('register', { 
      error: 'Користувач із таким іменем вже існує.', 
      csrfToken: req.session.csrfToken 
    });
  }


  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ username, password: hashedPassword, bio: 'Новий користувач' });

  res.render('login', { 
    error: null, 
    success: 'Реєстрація успішна! Увійдіть у систему.', 
    csrfToken: req.session.csrfToken 
  });
});

app.get('/login', (req, res) => {
  res.render('login', { error: null, success: null, csrfToken: req.session.csrfToken });
});

app.post('/login', loginLimiter, normalizeUsername, async (req, res) => {
  const { username, password } = req.body;

  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).render('login', { 
      error: 'Некоректні дані.', 
      success: null, 
      csrfToken: req.session.csrfToken 
    });
  }

  const user = users.find(u => u.username === username);
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(400).render('login', { 
      error: 'Невірне ім\'я користувача або пароль.', 
      success: null, 
      csrfToken: req.session.csrfToken 
    });
  }


  req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  req.session.user = { username: user.username, bio: user.bio };

  res.redirect('/profile');
});

app.get('/profile', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  const user = users.find(u => u.username === req.session.user.username);
  res.render('profile', { user, csrfToken: req.session.csrfToken });
});


app.post('/profile/update', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  const { bio } = req.body;
  const user = users.find(u => u.username === req.session.user.username);
  if (user && typeof bio === 'string') {
    user.bio = bio.slice(0, 150); 
  }
  res.redirect('/profile');
});


app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

app.use((req, res) => {
  res.status(404).render('404');
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).render('500', { message: 'Внутрішня помилка сервера.' });
});

app.listen(3000, () => {
  console.log('Сервер працює на http://localhost:3000');
});