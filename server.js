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

// Default admin credentials
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
// SCHEMA / MODEL
// =========================
const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      trim: true,
      default: 'User'
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true
    },
    password: {
      type: String,
      required: true
    },
    role: {
      type: String,
      enum: ['admin', 'member'],
      default: 'member'
    },
    isActive: {
      type: Boolean,
      default: true
    }
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
    title: 'Login | Financial Suite',
    error: options.error || null,
    success: options.success || null,
    mongoStatus: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected',
    serverStatus: 'Running'
  });
}

function renderDashboard(req, res, options = {}) {
  return res.render('app', {
    title: 'Dashboard | Financial Suite',
    user: req.session.user,
    error: options.error || null,
    success: options.success || null,
    mongoStatus: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected',
    serverStatus: 'Running'
  });
}

function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  next();
}

// =========================
// AUTO ADMIN SEED
// =========================
async function seedDefaultAdmin() {
  try {
    const existingAdmin = await User.findOne({ email: DEFAULT_ADMIN.email });

    if (!existingAdmin) {
      const hashedPassword = await bcrypt.hash(DEFAULT_ADMIN.password, BCRYPT_SALT_ROUNDS);

      await User.create({
        name: DEFAULT_ADMIN.name,
        email: DEFAULT_ADMIN.email,
        password: hashedPassword,
        role: DEFAULT_ADMIN.role,
        isActive: DEFAULT_ADMIN.isActive
      });

      console.log('âœ… Default admin user created');
      console.log(`Email: ${DEFAULT_ADMIN.email}`);
      console.log(`Password: ${DEFAULT_ADMIN.password}`);
    } else {
      console.log('â„¹ï¸ Default admin user already exists');
    }
  } catch (error) {
    console.error('âŒ Admin seed failed:', error.message);
  }
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
  renderLogin(res);
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return renderLogin(res, { error: 'Email and password are required.' });
    }

    const normalizedEmail = String(email).trim().toLowerCase();
    const user = await User.findOne({ email: normalizedEmail });

    if (!user) {
      return renderLogin(res, { error: 'Invalid email or password.' });
    }

    if (!user.isActive) {
      return renderLogin(res, { error: 'Your account is inactive. Please contact support.' });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return renderLogin(res, { error: 'Invalid email or password.' });
    }

    req.session.user = {
      id: user._id.toString(),
      name: user.name,
      email: user.email,
      role: user.role
    };

    return res.redirect('/app');
  } catch (error) {
    console.error('Login error:', error);
    return renderLogin(res, { error: 'An unexpected error occurred. Please try again.' });
  }
});

app.get('/app', requireAuth, (req, res) => {
  renderDashboard(req, res);
});

app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Logout error:', err);
      return res.redirect('/app');
    }
    res.clearCookie('connect.sid');
    return res.redirect('/login');
  });
});

app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    server: 'running',
    mongo: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  });
});

app.use((req, res) => {
  if (req.session.user) {
    return res.status(404).send('Page not found');
  }
  return res.redirect('/login');
});

// =========================
// START SERVER
// =========================
async function startServer() {
  try {
    await mongoose.connect(MONGODB_URI, {
      dbName: 'financial_suite'
    });

    console.log('âœ… MongoDB connected');
    console.log('Database: financial_suite');
    console.log('Collection: users');

    await seedDefaultAdmin();

    app.listen(PORT, () => {
      console.log(`âœ… Server running on port ${PORT}`);
    });
  } catch (error) {
    console.error('âŒ Failed to start server:', error.message);
    process.exit(1);
  }
}

startServer();
