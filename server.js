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

// =========================
// SECURITY / MIDDLEWARE
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
      secure: false, // set true behind HTTPS in production if needed
      maxAge: 1000 * 60 * 60 * 24 // 1 day
    }
  })
);

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// =========================
// MONGOOSE MODEL
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
    sessionUser: null,
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

// Optional health endpoint for Render
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    server: 'running',
    mongo: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  });
});

// =========================
// 404
// =========================
app.use((req, res) => {
  if (req.session.user) {
    return res.status(404).send('Page not found');
  }
  return res.redirect('/login');
});

// =========================
// STARTUP
// =========================
async function startServer() {
  try {
    await mongoose.connect(MONGODB_URI, {
      dbName: 'financial_suite'
    });

    console.log('MongoDB connected successfully');
    console.log(`Database: financial_suite`);
    console.log(`Collection: users`);

    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  } catch (error) {
    console.error('Failed to connect to MongoDB:', error.message);
    process.exit(1);
  }
}

startServer();

// =========================
// OPTIONAL SEED NOTE
// =========================
// To create an initial admin user, insert a user document in MongoDB Atlas
// with a bcrypt-hashed password. Example fields:
// name, email, password, role, isActive, createdAt
//
// Example hash generation (run locally if needed):
// bcrypt.hashSync('YourPassword123', 12)
