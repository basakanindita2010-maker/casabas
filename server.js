require('dotenv').config();

const express = require('express');
const session = require('express-session');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const path = require('path');

const app = express();

// =========================
// CONFIG
// =========================
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/financial_suite';
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-this-session-secret-in-production';
const BCRYPT_SALT_ROUNDS = 12;

const DEFAULT_ADMIN = {
  name: 'Admin User',
  email: 'admin@example.com',
  password: 'Admin@12345',
  role: 'admin',
  isActive: true
};

// =========================
// MIDDLEWARE
// =========================
app.use(helmet());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: false,
      maxAge: 1000 * 60 * 60 * 24
    }
  })
);

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// =========================
// MODEL
// =========================
const userSchema = new mongoose.Schema(
  {
    name: { type: String, trim: true, required: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true, index: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['admin', 'user'], default: 'user' },
    isActive: { type: Boolean, default: true }
  },
  {
    collection: 'users',
    timestamps: { createdAt: true, updatedAt: false }
  }
);

const User = mongoose.model('User', userSchema);

// =========================
// HELPERS
// =========================
function renderLogin(res, options = {}) {
  return res.render('login', {
    title: 'Financial Suite | Login',
    error: options.error || null,
    success: options.success || null,
    mode: options.mode || 'login',
    mongoStatus: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected',
    serverStatus: 'Running'
  });
}

async function getDashboardStats() {
  const totalUsers = await User.countDocuments();
  const activeUsers = await User.countDocuments({ isActive: true });
  const admins = await User.countDocuments({ role: 'admin' });
  return { totalUsers, activeUsers, admins };
}

async function renderApp(req, res, options = {}) {
  const stats = await getDashboardStats();
  return res.render('app', {
    title: 'Financial Suite | Dashboard',
    user: req.session.user,
    error: options.error || null,
    success: options.success || null,
    stats,
    mongoStatus: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected',
    serverStatus: 'Running'
  });
}

function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  if (req.session.user.role !== 'admin') return res.status(403).send('Forbidden');
  next();
}

// =========================
// SEED ADMIN
// =========================
async function seedDefaultAdmin() {
  const existing = await User.findOne({ email: DEFAULT_ADMIN.email });
  if (existing) return;

  const hashed = await bcrypt.hash(DEFAULT_ADMIN.password, BCRYPT_SALT_ROUNDS);
  await User.create({
    name: DEFAULT_ADMIN.name,
    email: DEFAULT_ADMIN.email,
    password: hashed,
    role: DEFAULT_ADMIN.role,
    isActive: DEFAULT_ADMIN.isActive
  });

  console.log('Default admin created:', DEFAULT_ADMIN.email);
}

// =========================
// ROUTES
// =========================
app.get('/', (req, res) => {
  if (req.session.user) return res.redirect('/app');
  return res.redirect('/login');
});

app.get('/login', (req, res) => {
  if (req.session.user) return res.redirect('/app');
  renderLogin(res, { mode: 'login' });
});

app.get('/register', (req, res) => {
  if (req.session.user) return res.redirect('/app');
  renderLogin(res, { mode: 'register' });
});

app.post('/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return renderLogin(res, { mode: 'register', error: 'All fields are required.' });
    }

    const normalizedEmail = String(email).trim().toLowerCase();
    const existing = await User.findOne({ email: normalizedEmail });

    if (existing) {
      return renderLogin(res, { mode: 'register', error: 'This email is already registered.' });
    }

    const hashed = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);

    const user = await User.create({
      name: String(name).trim(),
      email: normalizedEmail,
      password: hashed,
      role: 'user',
      isActive: true
    });

    req.session.user = {
      id: user._id.toString(),
      name: user.name,
      email: user.email,
      role: user.role
    };

    return res.redirect('/app');
  } catch (error) {
    console.error('Register error:', error);
    return renderLogin(res, { mode: 'register', error: 'Registration failed. Please try again.' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return renderLogin(res, { mode: 'login', error: 'Email and password are required.' });
    }

    const normalizedEmail = String(email).trim().toLowerCase();
    const user = await User.findOne({ email: normalizedEmail });

    if (!user) return renderLogin(res, { mode: 'login', error: 'Invalid email or password.' });
    if (!user.isActive) return renderLogin(res, { mode: 'login', error: 'Your account is inactive.' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return renderLogin(res, { mode: 'login', error: 'Invalid email or password.' });

    req.session.user = {
      id: user._id.toString(),
      name: user.name,
      email: user.email,
      role: user.role
    };

    return res.redirect('/app');
  } catch (error) {
    console.error('Login error:', error);
    return renderLogin(res, { mode: 'login', error: 'Login failed. Please try again.' });
  }
});

app.get('/app', requireAuth, async (req, res) => {
  return renderApp(req, res);
});

app.post('/change-password', requireAuth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) {
      return renderApp(req, res, { error: 'Current password and new password are required.' });
    }

    const user = await User.findById(req.session.user.id);
    if (!user) return req.session.destroy(() => res.redirect('/login'));

    const match = await bcrypt.compare(currentPassword, user.password);
    if (!match) return renderApp(req, res, { error: 'Current password is incorrect.' });

    user.password = await bcrypt.hash(newPassword, BCRYPT_SALT_ROUNDS);
    await user.save();

    return renderApp(req, res, { success: 'Password changed successfully.' });
  } catch (error) {
    console.error('Change password error:', error);
    return renderApp(req, res, { error: 'Unable to change password.' });
  }
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.redirect('/login');
  });
});

// Admin actions
app.post('/admin/toggle-user/:id', requireAdmin, async (req, res) => {
  try {
    const target = await User.findById(req.params.id);
    if (!target) return renderApp(req, res, { error: 'User not found.' });

    if (target.email === DEFAULT_ADMIN.email) {
      return renderApp(req, res, { error: 'Default admin cannot be deactivated.' });
    }

    target.isActive = !target.isActive;
    await target.save();

    return res.redirect('/app');
  } catch (error) {
    console.error('Toggle user error:', error);
    return renderApp(req, res, { error: 'Unable to update user status.' });
  }
});

app.post('/admin/change-role/:id', requireAdmin, async (req, res) => {
  try {
    const { role } = req.body;
    if (!['admin', 'user'].includes(role)) {
      return renderApp(req, res, { error: 'Invalid role selected.' });
    }

    const target = await User.findById(req.params.id);
    if (!target) return renderApp(req, res, { error: 'User not found.' });

    target.role = role;
    await target.save();

    return res.redirect('/app');
  } catch (error) {
    console.error('Change role error:', error);
    return renderApp(req, res, { error: 'Unable to change role.' });
  }
});

app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    server: 'running',
    mongo: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  });
});

app.use((req, res) => {
  if (req.session.user) return res.status(404).send('Page not found');
  return res.redirect('/login');
});

// =========================
// START
// =========================
async function startServer() {
  try {
    await mongoose.connect(MONGODB_URI, { dbName: 'financial_suite' });
    await seedDefaultAdmin();

    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  } catch (error) {
    console.error('Startup error:', error);
    process.exit(1);
  }
}

startServer();
