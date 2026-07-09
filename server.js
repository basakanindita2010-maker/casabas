'use strict';

require('dotenv').config();

const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const crypto = require('crypto');
const path = require('path');

const app = express();

const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;

if (!MONGODB_URI) {
  console.error('ERROR: Missing required environment variable MONGODB_URI.');
  console.error('Please define MONGODB_URI and restart the server.');
  process.exit(1);
}

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.set('trust proxy', 1);

app.use(bodyParser.urlencoded({ extended: false, limit: '4mb' }));
app.use(bodyParser.json({ limit: '4mb' }));
app.use(session({
  name: 'erp_sess',
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: false,
    maxAge: 1000 * 60 * 60 * 8
  }
}));

app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  res.locals.flash = req.session.flash || null;
  delete req.session.flash;
  next();
});

const roles = ['Administrator', 'Manager', 'Staff', 'Operator', 'Viewer'];

function flash(req, type, message) {
  req.session.flash = { type, message };
}

function money(v) {
  return new Intl.NumberFormat('en-IN', { style: 'currency', currency: 'INR', maximumFractionDigits: 0 }).format(Number(v || 0));
}

function fmtDate(v) {
  return v ? new Date(v).toLocaleDateString('en-IN') : '-';
}

function safeTrim(v) {
  return typeof v === 'string' ? v.trim() : '';
}

function hashPassword(pwd) {
  return crypto.createHash('sha256').update(String(pwd)).digest('hex');
}

function verifyPassword(pwd, hash) {
  return hashPassword(pwd) === hash;
}

function escapeRegex(s) {
  return String(s || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function toNum(v, d = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : d;
}

function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}

function hasRole(user, allowed) {
  return user && (user.role === 'Administrator' || allowed.includes(user.role));
}

async function audit(req, { action, entityType, entityId = null, before = null, after = null }) {
  try {
    await AuditLog.create({
      createdBy: req.session.user?._id || null,
      status: 'Active',
      actorEmail: req.session.user?.email || '',
      action,
      entityType,
      entityId,
      before,
      after,
      ip: req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || '',
      userAgent: req.headers['user-agent'] || '',
      path: req.originalUrl || ''
    });
  } catch (_) {}
}

const baseFields = {
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  status: { type: String, default: 'Active', index: true }
};

const userSchema = new mongoose.Schema({
  ...baseFields,
  fullName: String,
  email: { type: String, unique: true, lowercase: true, trim: true, index: true },
  passwordHash: String,
  role: { type: String, enum: roles, index: true },
  phone: String,
  mustChangePassword: { type: Boolean, default: false }
}, { timestamps: true });

const clientSchema = new mongoose.Schema({
  ...baseFields,
  clientCode: { type: String, unique: true, index: true },
  name: { type: String, index: 'text' },
  contactPerson: String,
  email: String,
  phone: String,
  address: String,
  gstNo: String,
  creditLimit: { type: Number, default: 0 },
  openingBalance: { type: Number, default: 0 }
}, { timestamps: true });

const stockItemSchema = new mongoose.Schema({
  ...baseFields,
  itemCode: { type: String, unique: true, index: true },
  itemName: { type: String, index: 'text' },
  category: { type: String, index: true },
  unit: String,
  openingQty: { type: Number, default: 0 },
  purchaseQty: { type: Number, default: 0 },
  saleQty: { type: Number, default: 0 },
  currentQty: { type: Number, default: 0, index: true },
  unitCost: { type: Number, default: 0 },
  salePrice: { type: Number, default: 0 },
  receivedAt: { type: Date, default: Date.now, index: true }
}, { timestamps: true });

const invoiceSchema = new mongoose.Schema({
  ...baseFields,
  invoiceNo: { type: String, unique: true, index: true },
  client: { type: mongoose.Schema.Types.ObjectId, ref: 'Client', index: true },
  invoiceDate: { type: Date, default: Date.now, index: true },
  dueDate: { type: Date, index: true },
  subtotal: { type: Number, default: 0 },
  tax: { type: Number, default: 0 },
  total: { type: Number, default: 0, index: true },
  paidAmount: { type: Number, default: 0 },
  balance: { type: Number, default: 0, index: true },
  paymentStatus: { type: String, default: 'Unpaid', index: true },
  notes: String
}, { timestamps: true });

const paymentSchema = new mongoose.Schema({
  ...baseFields,
  referenceNo: { type: String, unique: true, index: true },
  client: { type: mongoose.Schema.Types.ObjectId, ref: 'Client', index: true },
  invoice: { type: mongoose.Schema.Types.ObjectId, ref: 'Invoice', default: null, index: true },
  paymentDate: { type: Date, default: Date.now, index: true },
  amount: { type: Number, default: 0 },
  mode: { type: String, index: true },
  notes: String
}, { timestamps: true });

const bankStatementSchema = new mongoose.Schema({
  ...baseFields,
  statementDate: { type: Date, default: Date.now, index: true },
  description: { type: String, index: 'text' },
  reference: { type: String, index: true },
  debit: { type: Number, default: 0 },
  credit: { type: Number, default: 0 },
  balance: { type: Number, default: 0 },
  category: { type: String, default: 'Uncategorized', index: true },
  subCategory: { type: String, default: '' },
  matchedInvoice: { type: mongoose.Schema.Types.ObjectId, ref: 'Invoice', default: null, index: true },
  matchedClient: { type: mongoose.Schema.Types.ObjectId, ref: 'Client', default: null, index: true },
  notes: String
}, { timestamps: true });

const auditSchema = new mongoose.Schema({
  ...baseFields,
  actorEmail: String,
  action: { type: String, index: true },
  entityType: { type: String, index: true },
  entityId: mongoose.Schema.Types.ObjectId,
  before: mongoose.Schema.Types.Mixed,
  after: mongoose.Schema.Types.Mixed,
  ip: String,
  userAgent: String,
  path: String
}, { timestamps: true });

const activitySchema = new mongoose.Schema({
  ...baseFields,
  entityType: String,
  entityId: mongoose.Schema.Types.ObjectId,
  action: String,
  summary: String
}, { timestamps: true });

const settingSchema = new mongoose.Schema({
  ...baseFields,
  key: { type: String, unique: true, index: true },
  value: mongoose.Schema.Types.Mixed,
  description: String
}, { timestamps: true });

const notificationSchema = new mongoose.Schema({
  ...baseFields,
  title: String,
  message: String,
  severity: { type: String, default: 'info', index: true },
  isRead: { type: Boolean, default: false, index: true },
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null, index: true }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
const Client = mongoose.model('Client', clientSchema);
const StockItem = mongoose.model('StockItem', stockItemSchema);
const Invoice = mongoose.model('Invoice', invoiceSchema);
const Payment = mongoose.model('Payment', paymentSchema);
const BankStatement = mongoose.model('BankStatement', bankStatementSchema);
const AuditLog = mongoose.model('AuditLog', auditSchema);
const Activity = mongoose.model('Activity', activitySchema);
const Setting = mongoose.model('Setting', settingSchema);
const Notification = mongoose.model('Notification', notificationSchema);

async function seed() {
  const admin = await User.findOne({ email: 'admin@company.com' }).lean();
  if (!admin) {
    await User.create({
      fullName: 'System Administrator',
      email: 'admin@company.com',
      passwordHash: hashPassword('admin123'),
      role: 'Administrator',
      status: 'Active',
      createdBy: null
    });
  }

  const defaults = [
    ['app_name', 'ERP SaaS Suite'],
    ['company_name', 'Company'],
    ['currency', 'INR']
  ];
  for (const [key, value] of defaults) {
    const exists = await Setting.findOne({ key }).lean();
    if (!exists) await Setting.create({ key, value, description: key, status: 'Active' });
  }
}

async function logActivity(req, entityType, entityId, action, summary) {
  try {
    await Activity.create({
      createdBy: req.session.user?._id || null,
      status: 'Active',
      entityType,
      entityId,
      action,
      summary
    });
  } catch (_) {}
}

function parseQuery(q) {
  return {
    search: safeTrim(q.search),
    status: safeTrim(q.status),
    sort: safeTrim(q.sort) || 'createdAt',
    dir: safeTrim(q.dir) === 'asc' ? 1 : -1,
    page: Math.max(1, parseInt(q.pageNo || q.page || '1', 10)),
    limit: Math.min(100, Math.max(5, parseInt(q.limit || '10', 10)))
  };
}

function nav(user) {
  const items = [
    { key: 'dashboard', label: 'Dashboard', icon: 'fa-chart-line' },
    { key: 'clients', label: 'Clients', icon: 'fa-people-group' },
    { key: 'invoices', label: 'Invoices', icon: 'fa-file-invoice-dollar' },
    { key: 'payments', label: 'Payments', icon: 'fa-money-bill-transfer' },
    { key: 'bank', label: 'Bank Statements', icon: 'fa-building-columns' },
    { key: 'stock', label: 'Stock', icon: 'fa-boxes-stacked' },
    { key: 'reports', label: 'Reports', icon: 'fa-chart-column' },
    { key: 'notifications', label: 'Notifications', icon: 'fa-bell' },
    { key: 'audit', label: 'Audit Log', icon: 'fa-shield-halved' },
    { key: 'settings', label: 'Settings', icon: 'fa-gear' }
  ];
  if (user?.role === 'Administrator') items.splice(2, 0, { key: 'users', label: 'Users', icon: 'fa-user-shield' });
  return items;
}

function pageInfo(page) {
  const map = {
    dashboard: { title: 'Dashboard', icon: 'fa-chart-line' },
    clients: { title: 'Clients', icon: 'fa-people-group' },
    invoices: { title: 'Invoices', icon: 'fa-file-invoice-dollar' },
    payments: { title: 'Payments', icon: 'fa-money-bill-transfer' },
    bank: { title: 'Bank Statements', icon: 'fa-building-columns' },
    stock: { title: 'Stock Aging', icon: 'fa-boxes-stacked' },
    reports: { title: 'Reports', icon: 'fa-chart-column' },
    users: { title: 'Users', icon: 'fa-user-shield' },
    notifications: { title: 'Notifications', icon: 'fa-bell' },
    audit: { title: 'Audit Log', icon: 'fa-shield-halved' },
    settings: { title: 'Settings', icon: 'fa-gear' }
  };
  return map[page] || map.dashboard;
}

function ageBucket(days) {
  if (days <= 30) return '0-30';
  if (days <= 60) return '31-60';
  if (days <= 90) return '61-90';
  return '90+';
}

async function dashboardStats() {
  const [clients, invoices, payments, bankEntries, stockItems, unread] = await Promise.all([
    Client.countDocuments({}),
    Invoice.countDocuments({}),
    Payment.countDocuments({}),
    BankStatement.countDocuments({}),
    StockItem.countDocuments({}),
    Notification.countDocuments({ isRead: false })
  ]);
  const invAgg = await Invoice.aggregate([
    { $group: { _id: null, total: { $sum: '$total' }, paid: { $sum: '$paidAmount' }, balance: { $sum: '$balance' } } }
  ]);
  const stockAgg = await StockItem.aggregate([
    { $group: { _id: null, qty: { $sum: '$currentQty' }, value: { $sum: { $multiply: ['$currentQty', '$unitCost'] } } } }
  ]);
  return {
    clients,
    invoices,
    payments,
    bankEntries,
    stockItems,
    unread,
    finance: invAgg[0] || { total: 0, paid: 0, balance: 0 },
    stock: stockAgg[0] || { qty: 0, value: 0 }
  };
}

async function renderPage(req, res) {
  try {
    const page = safeTrim(req.query.page || 'dashboard');
    const { title, icon } = pageInfo(page);
    const stats = await dashboardStats();
    const sessionUser = await User.findById(req.session.user._id).lean();
    if (sessionUser) req.session.user = { _id: sessionUser._id, fullName: sessionUser.fullName, email: sessionUser.email, role: sessionUser.role };

    let payload = { records: [], total: 0, pageNo: 1, limit: 10, pages: 1, q: {} };
    let charts = {};
    let reportData = [];

    if (page === 'dashboard') {
      const [monthlyInvoice, monthlyPayments, monthlyBank, stockAge, debtorAge] = await Promise.all([
        Invoice.aggregate([
          { $group: { _id: { $dateToString: { format: '%Y-%m', date: '$invoiceDate' } }, total: { $sum: '$total' }, balance: { $sum: '$balance' } } },
          { $sort: { _id: 1 } },
          { $limit: 12 }
        ]),
        Payment.aggregate([
          { $group: { _id: { $dateToString: { format: '%Y-%m', date: '$paymentDate' } }, total: { $sum: '$amount' } } },
          { $sort: { _id: 1 } },
          { $limit: 12 }
        ]),
        BankStatement.aggregate([
          { $group: { _id: '$category', count: { $sum: 1 } } },
          { $sort: { count: -1 } }
        ]),
        StockItem.find({}).lean(),
        Invoice.find({ balance: { $gt: 0 } }).populate('client').lean()
      ]);

      const stockBuckets = { '0-30': 0, '31-60': 0, '61-90': 0, '90+': 0 };
      for (const item of stockAge) {
        const days = Math.max(0, Math.floor((Date.now() - new Date(item.receivedAt).getTime()) / (1000 * 60 * 60 * 24)));
        stockBuckets[ageBucket(days)] += item.currentQty;
      }

      const debtorBuckets = { '0-30': 0, '31-60': 0, '61-90': 0, '90+': 0 };
      for (const inv of debtorAge) {
        const days = Math.max(0, Math.floor((Date.now() - new Date(inv.invoiceDate).getTime()) / (1000 * 60 * 60 * 24)));
        debtorBuckets[ageBucket(days)] += inv.balance;
      }

      charts = { monthlyInvoice, monthlyPayments, monthlyBank, stockBuckets, debtorBuckets };

      payload.recentClients = await Client.find({}).sort({ createdAt: -1 }).limit(5).lean();
      payload.recentInvoices = await Invoice.find({}).populate('client').sort({ createdAt: -1 }).limit(5).lean();
    }

    if (page === 'clients') {
      const q = parseQuery(req.query);
      const filter = {};
      if (q.search) filter.$or = [
        { name: new RegExp(escapeRegex(q.search), 'i') },
        { clientCode: new RegExp(escapeRegex(q.search), 'i') },
        { email: new RegExp(escapeRegex(q.search), 'i') },
        { phone: new RegExp(escapeRegex(q.search), 'i') }
      ];
      if (q.status) filter.status = q.status;
      const total = await Client.countDocuments(filter);
      const records = await Client.find(filter).sort({ [q.sort]: q.dir }).skip((q.page - 1) * q.limit).limit(q.limit).lean();
      payload = { records, total, pageNo: q.page, limit: q.limit, pages: Math.max(1, Math.ceil(total / q.limit)), q };
    }

    if (page === 'users' && req.session.user.role === 'Administrator') {
      const q = parseQuery(req.query);
      const filter = {};
      if (q.search) filter.$or = [{ fullName: new RegExp(escapeRegex(q.search), 'i') }, { email: new RegExp(escapeRegex(q.search), 'i') }, { role: new RegExp(escapeRegex(q.search), 'i') }];
      const total = await User.countDocuments(filter);
      const records = await User.find(filter).select('-passwordHash').sort({ [q.sort]: q.dir }).skip((q.page - 1) * q.limit).limit(q.limit).lean();
      payload = { records, total, pageNo: q.page, limit: q.limit, pages: Math.max(1, Math.ceil(total / q.limit)), q };
    }

    if (page === 'invoices') {
      const q = parseQuery(req.query);
      const filter = {};
      if (q.search) filter.$or = [{ invoiceNo: new RegExp(escapeRegex(q.search), 'i') }, { paymentStatus: new RegExp(escapeRegex(q.search), 'i') }];
      const total = await Invoice.countDocuments(filter);
      const records = await Invoice.find(filter).populate('client').sort({ [q.sort]: q.dir }).skip((q.page - 1) * q.limit).limit(q.limit).lean();
      payload = { records, total, pageNo: q.page, limit: q.limit, pages: Math.max(1, Math.ceil(total / q.limit)), q };
    }

    if (page === 'payments') {
      const q = parseQuery(req.query);
      const filter = {};
      if (q.search) filter.$or = [{ referenceNo: new RegExp(escapeRegex(q.search), 'i') }, { mode: new RegExp(escapeRegex(q.search), 'i') }];
      const total = await Payment.countDocuments(filter);
      const records = await Payment.find(filter).populate('client invoice').sort({ [q.sort]: q.dir }).skip((q.page - 1) * q.limit).limit(q.limit).lean();
      payload = { records, total, pageNo: q.page, limit: q.limit, pages: Math.max(1, Math.ceil(total / q.limit)), q };
    }

    if (page === 'bank') {
      const q = parseQuery(req.query);
      const filter = {};
      if (q.search) filter.$or = [
        { description: new RegExp(escapeRegex(q.search), 'i') },
        { reference: new RegExp(escapeRegex(q.search), 'i') },
        { category: new RegExp(escapeRegex(q.search), 'i') }
      ];
      if (q.status) filter.status = q.status;
      const total = await BankStatement.countDocuments(filter);
      const records = await BankStatement.find(filter).populate('matchedInvoice matchedClient').sort({ statementDate: -1 }).skip((q.page - 1) * q.limit).limit(q.limit).lean();
      payload = { records, total, pageNo: q.page, limit: q.limit, pages: Math.max(1, Math.ceil(total / q.limit)), q };
    }

    if (page === 'stock') {
      const q = parseQuery(req.query);
      const filter = {};
      if (q.search) filter.$or = [
        { itemName: new RegExp(escapeRegex(q.search), 'i') },
        { itemCode: new RegExp(escapeRegex(q.search), 'i') },
        { category: new RegExp(escapeRegex(q.search), 'i') }
      ];
      const total = await StockItem.countDocuments(filter);
      const records = await StockItem.find(filter).sort({ [q.sort]: q.dir }).skip((q.page - 1) * q.limit).limit(q.limit).lean();
      payload = { records, total, pageNo: q.page, limit: q.limit, pages: Math.max(1, Math.ceil(total / q.limit)), q };
    }

    if (page === 'reports') {
      reportData = await Invoice.find({}).populate('client').sort({ invoiceDate: -1 }).lean();
      const debtorAgeing = await Invoice.find({ balance: { $gt: 0 } }).populate('client').lean();
      const stockItems = await StockItem.find({}).lean();
      const bankItems = await BankStatement.find({}).populate('matchedClient matchedInvoice').sort({ statementDate: -1 }).lean();
      charts = {
        debtorAgeing,
        stockItems,
        bankItems
      };
    }

    if (page === 'notifications') {
      const q = parseQuery(req.query);
      const total = await Notification.countDocuments({});
      const records = await Notification.find({}).populate('user').sort({ createdAt: -1 }).skip((q.page - 1) * q.limit).limit(q.limit).lean();
      payload = { records, total, pageNo: q.page, limit: q.limit, pages: Math.max(1, Math.ceil(total / q.limit)), q };
    }

    if (page === 'audit') {
      const q = parseQuery(req.query);
      const total = await AuditLog.countDocuments({});
      const records = await AuditLog.find({}).sort({ createdAt: -1 }).skip((q.page - 1) * q.limit).limit(q.limit).lean();
      payload = { records, total, pageNo: q.page, limit: q.limit, pages: Math.max(1, Math.ceil(total / q.limit)), q };
    }

    res.render('app', {
      page,
      title,
      icon,
      stats,
      payload,
      charts,
      reportData,
      nav: nav(req.session.user),
      user: req.session.user,
      money,
      fmtDate,
      roles,
      flash: res.locals.flash,
      appName: 'ERP SaaS Suite'
    });
  } catch (err) {
    res.status(500).send('Server error');
  }
}

app.get('/', (req, res) => req.session.user ? res.redirect('/app?page=dashboard') : res.redirect('/login'));

app.get('/login', (req, res) => {
  if (req.session.user) return res.redirect('/app?page=dashboard');
  res.render('login', { appName: 'ERP SaaS Suite', flash: res.locals.flash });
});

app.post('/login', async (req, res) => {
  try {
    const email = safeTrim(req.body.email).toLowerCase();
    const password = safeTrim(req.body.password);
    const remember = req.body.remember === 'on';

    if (!email || !password) {
      flash(req, 'danger', 'Email and password are required.');
      return res.redirect('/login');
    }

    const user = await User.findOne({ email }).lean();
    if (!user || !verifyPassword(password, user.passwordHash) || user.status !== 'Active') {
      flash(req, 'danger', 'Invalid credentials.');
      return res.redirect('/login');
    }

    req.session.regenerate(async (err) => {
      if (err) {
        flash(req, 'danger', 'Unable to create session.');
        return res.redirect('/login');
      }
      req.session.user = { _id: user._id, fullName: user.fullName, email: user.email, role: user.role };
      req.session.cookie.maxAge = remember ? 1000 * 60 * 60 * 24 * 30 : 1000 * 60 * 60 * 8;
      await User.updateOne({ _id: user._id }, { $set: { lastLoginAt: new Date() } });
      await audit(req, { action: 'Login', entityType: 'User', entityId: user._id, after: { email: user.email } });
      return res.redirect('/app?page=dashboard');
    });
  } catch (err) {
    flash(req, 'danger', 'Login failed.');
    return res.redirect('/login');
  }
});

app.post('/logout', requireAuth, async (req, res) => {
  try {
    await audit(req, { action: 'Logout', entityType: 'User', entityId: req.session.user._id });
  } catch (_) {}
  req.session.destroy(() => res.redirect('/login'));
});

app.post('/forgot-password', async (req, res) => {
  try {
    const email = safeTrim(req.body.email).toLowerCase();
    const user = await User.findOne({ email });
    if (user) {
      const token = crypto.randomBytes(32).toString('hex');
      user.passwordResetTokenHash = hashPassword(token);
      user.passwordResetExpiresAt = new Date(Date.now() + 1000 * 60 * 30);
      await user.save();
      await audit(req, { action: 'Settings', entityType: 'User', entityId: user._id, after: { resetRequested: true } });
    }
    flash(req, 'info', 'If the account exists, a reset flow has been created.');
    res.redirect('/login');
  } catch (err) {
    res.redirect('/login');
  }
});

app.post('/app/:entity/:action', requireAuth, async (req, res) => {
  try {
    const entity = safeTrim(req.params.entity);
    const action = safeTrim(req.params.action);
    const page = safeTrim(req.query.page || entity);
    const back = `/app?page=${encodeURIComponent(page)}`;

    const modelMap = {
      clients: Client,
      users: User,
      invoices: Invoice,
      payments: Payment,
      bank: BankStatement,
      stock: StockItem,
      notifications: Notification,
      settings: Setting
    };
    const Model = modelMap[entity];
    if (!Model) return res.redirect(back);

    const body = req.body || {};
    const id = body.id;

    if (action === 'create') {
      let doc = { createdBy: req.session.user._id, status: body.status || 'Active' };

      if (entity === 'clients') {
        doc = { ...doc, clientCode: body.clientCode || `CL-${Date.now()}`, name: body.name, contactPerson: body.contactPerson, email: body.email, phone: body.phone, address: body.address, gstNo: body.gstNo, creditLimit: toNum(body.creditLimit, 0), openingBalance: toNum(body.openingBalance, 0) };
      }
      if (entity === 'users') {
        doc = { ...doc, fullName: body.fullName, email: body.email, passwordHash: hashPassword(body.password || 'ChangeMe123!'), role: body.role, phone: body.phone, mustChangePassword: true };
      }
      if (entity === 'invoices') {
        const subtotal = toNum(body.subtotal, 0);
        const tax = toNum(body.tax, 0);
        const paid = toNum(body.paidAmount, 0);
        const total = subtotal + tax;
        doc = { ...doc, invoiceNo: body.invoiceNo || `INV-${Date.now()}`, client: body.clientId, invoiceDate: body.invoiceDate || new Date(), dueDate: body.dueDate || null, subtotal, tax, total, paidAmount: paid, balance: Math.max(0, total - paid), paymentStatus: body.paymentStatus || (paid >= total ? 'Paid' : 'Unpaid'), notes: body.notes };
      }
      if (entity === 'payments') {
        doc = { ...doc, referenceNo: body.referenceNo || `PAY-${Date.now()}`, client: body.clientId, invoice: body.invoiceId || null, paymentDate: body.paymentDate || new Date(), amount: toNum(body.amount, 0), mode: body.mode, notes: body.notes };
      }
      if (entity === 'bank') {
        doc = { ...doc, statementDate: body.statementDate || new Date(), description: body.description, reference: body.reference, debit: toNum(body.debit, 0), credit: toNum(body.credit, 0), balance: toNum(body.balance, 0), category: body.category || 'Uncategorized', subCategory: body.subCategory || '', matchedInvoice: body.matchedInvoice || null, matchedClient: body.matchedClient || null, notes: body.notes };
      }
      if (entity === 'stock') {
        const openingQty = toNum(body.openingQty, 0);
        const purchaseQty = toNum(body.purchaseQty, 0);
        const saleQty = toNum(body.saleQty, 0);
        doc = { ...doc, itemCode: body.itemCode || `IT-${Date.now()}`, itemName: body.itemName, category: body.category, unit: body.unit, openingQty, purchaseQty, saleQty, currentQty: openingQty + purchaseQty - saleQty, unitCost: toNum(body.unitCost, 0), salePrice: toNum(body.salePrice, 0), receivedAt: body.receivedAt || new Date() };
      }
      if (entity === 'notifications') {
        doc = { ...doc, title: body.title, message: body.message, severity: body.severity || 'info', isRead: body.isRead === 'on' || body.isRead === 'true' };
      }
      if (entity === 'settings') {
        doc = { ...doc, key: body.key, value: body.value, description: body.description };
      }

      const created = await Model.create(doc);
      await logActivity(req, entity, created._id, 'Create', `${entity} created`);
      await audit(req, { action: 'Insert', entityType: entity, entityId: created._id, after: doc });
      flash(req, 'success', `${entity} created successfully.`);
      return res.redirect(back);
    }

    if (!id) return res.redirect(back);
    const before = await Model.findById(id).lean();
    if (!before) {
      flash(req, 'danger', 'Record not found.');
      return res.redirect(back);
    }

    if (action === 'update') {
      let update = { status: body.status || before.status };

      if (entity === 'clients') update = { ...update, clientCode: body.clientCode, name: body.name, contactPerson: body.contactPerson, email: body.email, phone: body.phone, address: body.address, gstNo: body.gstNo, creditLimit: toNum(body.creditLimit, 0), openingBalance: toNum(body.openingBalance, 0) };
      if (entity === 'users') update = { ...update, fullName: body.fullName, email: body.email, role: body.role, phone: body.phone };
      if (entity === 'invoices') {
        const subtotal = toNum(body.subtotal, 0);
        const tax = toNum(body.tax, 0);
        const paid = toNum(body.paidAmount, 0);
        const total = subtotal + tax;
        update = { ...update, invoiceNo: body.invoiceNo, client: body.clientId, invoiceDate: body.invoiceDate, dueDate: body.dueDate || null, subtotal, tax, total, paidAmount: paid, balance: Math.max(0, total - paid), paymentStatus: body.paymentStatus, notes: body.notes };
      }
      if (entity === 'payments') update = { ...update, referenceNo: body.referenceNo, client: body.clientId, invoice: body.invoiceId || null, paymentDate: body.paymentDate, amount: toNum(body.amount, 0), mode: body.mode, notes: body.notes };
      if (entity === 'bank') update = { ...update, statementDate: body.statementDate, description: body.description, reference: body.reference, debit: toNum(body.debit, 0), credit: toNum(body.credit, 0), balance: toNum(body.balance, 0), category: body.category, subCategory: body.subCategory, matchedInvoice: body.matchedInvoice || null, matchedClient: body.matchedClient || null, notes: body.notes };
      if (entity === 'stock') {
        const openingQty = toNum(body.openingQty, 0);
        const purchaseQty = toNum(body.purchaseQty, 0);
        const saleQty = toNum(body.saleQty, 0);
        update = { ...update, itemCode: body.itemCode, itemName: body.itemName, category: body.category, unit: body.unit, openingQty, purchaseQty, saleQty, currentQty: openingQty + purchaseQty - saleQty, unitCost: toNum(body.unitCost, 0), salePrice: toNum(body.salePrice, 0), receivedAt: body.receivedAt };
      }
      if (entity === 'notifications') update = { ...update, title: body.title, message: body.message, severity: body.severity, isRead: body.isRead === 'on' || body.isRead === 'true' };
      if (entity === 'settings') update = { ...update, key: body.key, value: body.value, description: body.description };

      const updated = await Model.findByIdAndUpdate(id, update, { new: true });
      await logActivity(req, entity, updated._id, 'Update', `${entity} updated`);
      await audit(req, { action: 'Update', entityType: entity, entityId: updated._id, before, after: update });
      flash(req, 'success', `${entity} updated successfully.`);
      return res.redirect(back);
    }

    if (action === 'delete') {
      await Model.findByIdAndDelete(id);
      await logActivity(req, entity, id, 'Delete', `${entity} deleted`);
      await audit(req, { action: 'Delete', entityType: entity, entityId: id, before });
      flash(req, 'success', `${entity} deleted successfully.`);
      return res.redirect(back);
    }

    if (action === 'categorize' && entity === 'bank') {
      const category = body.category || 'Uncategorized';
      const subCategory = body.subCategory || '';
      const matchedInvoice = body.matchedInvoice || null;
      const matchedClient = body.matchedClient || null;
      const updated = await BankStatement.findByIdAndUpdate(id, { category, subCategory, matchedInvoice, matchedClient }, { new: true });
      await audit(req, { action: 'Update', entityType: entity, entityId: id, before, after: updated });
      flash(req, 'success', 'Bank statement categorized successfully.');
      return res.redirect(back);
    }

    flash(req, 'danger', 'Unsupported action.');
    return res.redirect(back);
  } catch (err) {
    flash(req, 'danger', 'Operation failed.');
    return res.redirect(`/app?page=${encodeURIComponent(req.query.page || 'dashboard')}`);
  }
});

app.get('/export/:entity', requireAuth, async (req, res) => {
  try {
    const entity = safeTrim(req.params.entity);
    const modelMap = { clients: Client, users: User, invoices: Invoice, payments: Payment, bank: BankStatement, stock: StockItem, notifications: Notification, audit: AuditLog };
    const Model = modelMap[entity];
    if (!Model) return res.redirect('/app?page=dashboard');

    const docs = await Model.find({}).lean();
    await audit(req, { action: 'Export', entityType: entity, entityId: null, after: { count: docs.length } });

    const cols = Object.keys(docs[0] || { noData: '' });
    const csv = [cols.join(','), ...docs.map(d => cols.map(c => JSON.stringify(d[c] ?? '')).join(','))].join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${entity}-${Date.now()}.csv"`);
    return res.send(csv);
  } catch (err) {
    flash(req, 'danger', 'Export failed.');
    return res.redirect('/app?page=dashboard');
  }
});

app.get('/print/:entity', requireAuth, async (req, res) => {
  try {
    await audit(req, { action: 'Print', entityType: safeTrim(req.params.entity), entityId: null });
    return renderPage(req, res);
  } catch (err) {
    return res.redirect('/app?page=dashboard');
  }
});

app.use((req, res) => {
  if (req.session.user) return res.redirect('/app?page=dashboard');
  return res.redirect('/login');
});

mongoose.connect(MONGODB_URI, { autoIndex: true })
  .then(async () => {
    await seed();
    app.listen(PORT, () => console.log(`ERP SaaS Suite running on port ${PORT}`));
  })
  .catch(err => {
    console.error('ERROR: MongoDB connection failed.');
    console.error(err.message || err);
    process.exit(1);
  });
