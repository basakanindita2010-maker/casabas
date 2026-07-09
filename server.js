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
  console.error('ERROR: MONGODB_URI is required.');
  process.exit(1);
}

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.set('trust proxy', 1);

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

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
  res.locals.flash = req.session.flash || null;
  delete req.session.flash;
  next();
});

function flash(req, type, message) {
  req.session.flash = { type, message };
}

function safeTrim(v) {
  return typeof v === 'string' ? v.trim() : '';
}

function hashPassword(v) {
  return crypto.createHash('sha256').update(String(v)).digest('hex');
}

function verifyPassword(v, hash) {
  return hashPassword(v) === hash;
}

function money(v) {
  return new Intl.NumberFormat('en-IN', { style: 'currency', currency: 'INR', maximumFractionDigits: 0 }).format(Number(v || 0));
}

function fmtDate(v) {
  return v ? new Date(v).toLocaleDateString('en-IN') : '-';
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

const roles = ['Administrator', 'Manager', 'Staff', 'Operator', 'Viewer'];

const base = {
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  status: { type: String, default: 'Active', index: true }
};

const User = mongoose.model('User', new mongoose.Schema({
  ...base,
  fullName: String,
  email: { type: String, unique: true, lowercase: true, trim: true, index: true },
  passwordHash: String,
  role: { type: String, enum: roles, index: true },
  phone: String,
  mustChangePassword: { type: Boolean, default: false }
}, { timestamps: true }));

const Client = mongoose.model('Client', new mongoose.Schema({
  ...base,
  clientCode: { type: String, unique: true, index: true },
  name: { type: String, index: 'text' },
  contactPerson: String,
  email: String,
  phone: String,
  address: String,
  gstNo: String,
  creditLimit: { type: Number, default: 0 },
  openingBalance: { type: Number, default: 0 }
}, { timestamps: true }));

const StockItem = mongoose.model('StockItem', new mongoose.Schema({
  ...base,
  itemCode: { type: String, unique: true, index: true },
  itemName: { type: String, index: 'text' },
  category: { type: String, index: true },
  unit: String,
  openingQty: { type: Number, default: 0 },
  purchaseQty: { type: Number, default: 0 },
  saleQty: { type: Number, default: 0 },
  currentQty: { type: Number, default: 0 },
  unitCost: { type: Number, default: 0 },
  salePrice: { type: Number, default: 0 },
  receivedAt: { type: Date, default: Date.now }
}, { timestamps: true }));

const Invoice = mongoose.model('Invoice', new mongoose.Schema({
  ...base,
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
}, { timestamps: true }));

const Payment = mongoose.model('Payment', new mongoose.Schema({
  ...base,
  referenceNo: { type: String, unique: true, index: true },
  client: { type: mongoose.Schema.Types.ObjectId, ref: 'Client', index: true },
  invoice: { type: mongoose.Schema.Types.ObjectId, ref: 'Invoice', default: null, index: true },
  paymentDate: { type: Date, default: Date.now, index: true },
  amount: { type: Number, default: 0 },
  mode: { type: String, index: true },
  notes: String
}, { timestamps: true }));

const BankStatement = mongoose.model('BankStatement', new mongoose.Schema({
  ...base,
  statementDate: { type: Date, default: Date.now, index: true },
  description: { type: String, index: 'text' },
  reference: { type: String, index: true },
  debit: { type: Number, default: 0 },
  credit: { type: Number, default: 0 },
  balance: { type: Number, default: 0 },
  category: { type: String, default: 'Uncategorized', index: true },
  subCategory: { type: String, default: '' },
  matchedInvoice: { type: mongoose.Schema.Types.ObjectId, ref: 'Invoice', default: null },
  matchedClient: { type: mongoose.Schema.Types.ObjectId, ref: 'Client', default: null },
  notes: String
}, { timestamps: true }));

const AuditLog = mongoose.model('AuditLog', new mongoose.Schema({
  ...base,
  actorEmail: String,
  action: String,
  entityType: String,
  entityId: mongoose.Schema.Types.ObjectId,
  before: mongoose.Schema.Types.Mixed,
  after: mongoose.Schema.Types.Mixed,
  ip: String,
  userAgent: String,
  path: String
}, { timestamps: true }));

const Activity = mongoose.model('Activity', new mongoose.Schema({
  ...base,
  entityType: String,
  entityId: mongoose.Schema.Types.ObjectId,
  action: String,
  summary: String
}, { timestamps: true }));

const Setting = mongoose.model('Setting', new mongoose.Schema({
  ...base,
  key: { type: String, unique: true, index: true },
  value: mongoose.Schema.Types.Mixed,
  description: String
}, { timestamps: true }));

const Notification = mongoose.model('Notification', new mongoose.Schema({
  ...base,
  title: String,
  message: String,
  severity: { type: String, default: 'info' },
  isRead: { type: Boolean, default: false },
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null }
}, { timestamps: true }));

async function seed() {
  const adminEmail = 'admin@company.com';
  const adminPassword = 'admin123';

  await User.updateOne(
    { email: adminEmail },
    {
      $set: {
        fullName: 'System Administrator',
        email: adminEmail,
        passwordHash: hashPassword(adminPassword),
        role: 'Administrator',
        status: 'Active',
        mustChangePassword: false
      }
    },
    { upsert: true }
  );

  const defs = [
    ['app_name', 'ERP SaaS Suite'],
    ['company_name', 'Company']
  ];
  for (const [key, value] of defs) {
    const exists = await Setting.findOne({ key }).lean();
    if (!exists) await Setting.create({ key, value, description: key, status: 'Active' });
  }
}

function nav(user) {
  const items = [
    { key: 'dashboard', label: 'Dashboard', icon: 'fa-chart-line' },
    { key: 'clients', label: 'Clients', icon: 'fa-people-group' },
    { key: 'users', label: 'Users', icon: 'fa-user-shield' },
    { key: 'invoices', label: 'Invoices', icon: 'fa-file-invoice-dollar' },
    { key: 'payments', label: 'Payments', icon: 'fa-money-bill-transfer' },
    { key: 'bank', label: 'Bank Statements', icon: 'fa-building-columns' },
    { key: 'stock', label: 'Stock Aging', icon: 'fa-boxes-stacked' },
    { key: 'reports', label: 'Reports', icon: 'fa-chart-column' },
    { key: 'notifications', label: 'Notifications', icon: 'fa-bell' },
    { key: 'audit', label: 'Audit Log', icon: 'fa-shield-halved' },
    { key: 'settings', label: 'Settings', icon: 'fa-gear' }
  ];
  if (user?.role !== 'Administrator') return items.filter(x => x.key !== 'users' && x.key !== 'settings');
  return items;
}

function pageInfo(page) {
  const map = {
    dashboard: ['Dashboard', 'fa-chart-line'],
    clients: ['Clients', 'fa-people-group'],
    users: ['Users', 'fa-user-shield'],
    invoices: ['Invoices', 'fa-file-invoice-dollar'],
    payments: ['Payments', 'fa-money-bill-transfer'],
    bank: ['Bank Statements', 'fa-building-columns'],
    stock: ['Stock Aging', 'fa-boxes-stacked'],
    reports: ['Reports', 'fa-chart-column'],
    notifications: ['Notifications', 'fa-bell'],
    audit: ['Audit Log', 'fa-shield-halved'],
    settings: ['Settings', 'fa-gear']
  };
  const v = map[page] || map.dashboard;
  return { title: v[0], icon: v[1] };
}

async function audit(req, data) {
  try {
    await AuditLog.create({
      createdBy: req.session.user?._id || null,
      status: 'Active',
      actorEmail: req.session.user?.email || '',
      ip: req.socket.remoteAddress || '',
      userAgent: req.headers['user-agent'] || '',
      path: req.originalUrl || '',
      ...data
    });
  } catch (_) {}
}

async function renderApp(req, res) {
  const page = safeTrim(req.query.page || 'dashboard');
  const { title, icon } = pageInfo(page);

  const stats = {
    clients: await Client.countDocuments({}),
    invoices: await Invoice.countDocuments({}),
    payments: await Payment.countDocuments({}),
    bank: await BankStatement.countDocuments({}),
    stock: await StockItem.countDocuments({}),
    unread: await Notification.countDocuments({ isRead: false })
  };

  const invAgg = await Invoice.aggregate([{ $group: { _id: null, total: { $sum: '$total' }, paid: { $sum: '$paidAmount' }, balance: { $sum: '$balance' } } }]);
  const finance = invAgg[0] || { total: 0, paid: 0, balance: 0 };

  let payload = { records: [], total: 0, pageNo: 1, limit: 10, pages: 1, q: {} };
  let charts = {};

  if (page === 'dashboard') {
    charts.invoiceMonthly = await Invoice.aggregate([{ $group: { _id: { $dateToString: { format: '%Y-%m', date: '$invoiceDate' } }, total: { $sum: '$total' } } }, { $sort: { _id: 1 } }, { $limit: 12 }]);
    charts.paymentMonthly = await Payment.aggregate([{ $group: { _id: { $dateToString: { format: '%Y-%m', date: '$paymentDate' } }, total: { $sum: '$amount' } } }, { $sort: { _id: 1 } }, { $limit: 12 }]);
    const stock = await StockItem.find({}).lean();
    const debtors = await Invoice.find({ balance: { $gt: 0 } }).populate('client').lean();
    const stockBuckets = { '0-30': 0, '31-60': 0, '61-90': 0, '90+': 0 };
    const debtorBuckets = { '0-30': 0, '31-60': 0, '61-90': 0, '90+': 0 };
    for (const s of stock) {
      const days = Math.floor((Date.now() - new Date(s.receivedAt).getTime()) / 86400000);
      if (days <= 30) stockBuckets['0-30'] += s.currentQty;
      else if (days <= 60) stockBuckets['31-60'] += s.currentQty;
      else if (days <= 90) stockBuckets['61-90'] += s.currentQty;
      else stockBuckets['90+'] += s.currentQty;
    }
    for (const d of debtors) {
      const days = Math.floor((Date.now() - new Date(d.invoiceDate).getTime()) / 86400000);
      if (days <= 30) debtorBuckets['0-30'] += d.balance;
      else if (days <= 60) debtorBuckets['31-60'] += d.balance;
      else if (days <= 90) debtorBuckets['61-90'] += d.balance;
      else debtorBuckets['90+'] += d.balance;
    }
    charts.stockBuckets = stockBuckets;
    charts.debtorBuckets = debtorBuckets;
  }

  if (page === 'clients') payload.records = await Client.find({}).sort({ createdAt: -1 }).lean();
  if (page === 'users' && req.session.user.role === 'Administrator') payload.records = await User.find({}).select('-passwordHash').sort({ createdAt: -1 }).lean();
  if (page === 'invoices') payload.records = await Invoice.find({}).populate('client').sort({ createdAt: -1 }).lean();
  if (page === 'payments') payload.records = await Payment.find({}).populate('client invoice').sort({ createdAt: -1 }).lean();
  if (page === 'bank') payload.records = await BankStatement.find({}).populate('matchedClient matchedInvoice').sort({ statementDate: -1 }).lean();
  if (page === 'stock') payload.records = await StockItem.find({}).sort({ createdAt: -1 }).lean();
  if (page === 'notifications') payload.records = await Notification.find({}).populate('user').sort({ createdAt: -1 }).lean();
  if (page === 'audit') payload.records = await AuditLog.find({}).sort({ createdAt: -1 }).lean();

  payload.total = payload.records.length;

  res.render('app', {
    appName: 'ERP SaaS Suite',
    page,
    title,
    icon,
    stats,
    finance,
    payload,
    charts,
    nav: nav(req.session.user),
    user: req.session.user,
    money,
    fmtDate,
    flash: res.locals.flash
  });
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

    const user = await User.findOne({ email }).lean();
    if (!user || !verifyPassword(password, user.passwordHash) || user.status !== 'Active') {
      flash(req, 'danger', 'Invalid credentials.');
      return res.redirect('/login');
    }

    req.session.regenerate(async (err) => {
      if (err) {
        flash(req, 'danger', 'Session error.');
        return res.redirect('/login');
      }
      req.session.user = { _id: user._id, fullName: user.fullName, email: user.email, role: user.role };
      req.session.cookie.maxAge = remember ? 1000 * 60 * 60 * 24 * 30 : 1000 * 60 * 60 * 8;
      await audit(req, { action: 'Login', entityType: 'User', entityId: user._id });
      return res.redirect('/app?page=dashboard');
    });
  } catch (err) {
    flash(req, 'danger', 'Login failed.');
    return res.redirect('/login');
  }
});

app.post('/logout', requireAuth, async (req, res) => {
  await audit(req, { action: 'Logout', entityType: 'User', entityId: req.session.user._id });
  req.session.destroy(() => res.redirect('/login'));
});

app.post('/forgot-password', async (req, res) => {
  flash(req, 'info', 'Reset architecture created. Integrate email delivery for production.');
  return res.redirect('/login');
});

app.post('/app/:entity/:action', requireAuth, async (req, res) => {
  try {
    const entity = req.params.entity;
    const action = req.params.action;
    const page = safeTrim(req.query.page || entity);
    const back = `/app?page=${encodeURIComponent(page)}`;
    const body = req.body || {};

    const models = { clients: Client, users: User, invoices: Invoice, payments: Payment, bank: BankStatement, stock: StockItem, notifications: Notification, settings: Setting };
    const Model = models[entity];
    if (!Model) return res.redirect(back);

    if (entity === 'users' && req.session.user.role !== 'Administrator') {
      flash(req, 'danger', 'Access denied.');
      return res.redirect(back);
    }

    if (action === 'create') {
      let doc = { createdBy: req.session.user._id, status: body.status || 'Active' };
      if (entity === 'clients') doc = { ...doc, clientCode: body.clientCode || `CL-${Date.now()}`, name: body.name, contactPerson: body.contactPerson, email: body.email, phone: body.phone, address: body.address, gstNo: body.gstNo, creditLimit: toNum(body.creditLimit), openingBalance: toNum(body.openingBalance) };
      if (entity === 'users') doc = { ...doc, fullName: body.fullName, email: body.email, passwordHash: hashPassword(body.password || 'ChangeMe123!'), role: body.role, phone: body.phone, mustChangePassword: true };
      if (entity === 'invoices') {
        const subtotal = toNum(body.subtotal), tax = toNum(body.tax), paidAmount = toNum(body.paidAmount);
        const total = subtotal + tax;
        doc = { ...doc, invoiceNo: body.invoiceNo || `INV-${Date.now()}`, client: body.clientId, invoiceDate: body.invoiceDate || new Date(), dueDate: body.dueDate || null, subtotal, tax, total, paidAmount, balance: Math.max(0, total - paidAmount), paymentStatus: body.paymentStatus || (paidAmount >= total ? 'Paid' : 'Unpaid'), notes: body.notes };
      }
      if (entity === 'payments') doc = { ...doc, referenceNo: body.referenceNo || `PAY-${Date.now()}`, client: body.clientId, invoice: body.invoiceId || null, paymentDate: body.paymentDate || new Date(), amount: toNum(body.amount), mode: body.mode, notes: body.notes };
      if (entity === 'bank') doc = { ...doc, statementDate: body.statementDate || new Date(), description: body.description, reference: body.reference, debit: toNum(body.debit), credit: toNum(body.credit), balance: toNum(body.balance), category: body.category || 'Uncategorized', subCategory: body.subCategory || '', matchedInvoice: body.matchedInvoice || null, matchedClient: body.matchedClient || null, notes: body.notes };
      if (entity === 'stock') {
        const openingQty = toNum(body.openingQty), purchaseQty = toNum(body.purchaseQty), saleQty = toNum(body.saleQty);
        doc = { ...doc, itemCode: body.itemCode || `IT-${Date.now()}`, itemName: body.itemName, category: body.category, unit: body.unit, openingQty, purchaseQty, saleQty, currentQty: openingQty + purchaseQty - saleQty, unitCost: toNum(body.unitCost), salePrice: toNum(body.salePrice), receivedAt: body.receivedAt || new Date() };
      }
      if (entity === 'notifications') doc = { ...doc, title: body.title, message: body.message, severity: body.severity || 'info', isRead: body.isRead === 'on' };
      const created = await Model.create(doc);
      await audit(req, { action: 'Insert', entityType: entity, entityId: created._id, after: doc });
      flash(req, 'success', `${entity} created successfully.`);
      return res.redirect(back);
    }

    if (action === 'update') {
      const id = body.id;
      const before = await Model.findById(id).lean();
      if (!before) return res.redirect(back);
      let update = { status: body.status || before.status };
      if (entity === 'clients') update = { ...update, clientCode: body.clientCode, name: body.name, contactPerson: body.contactPerson, email: body.email, phone: body.phone, address: body.address, gstNo: body.gstNo, creditLimit: toNum(body.creditLimit), openingBalance: toNum(body.openingBalance) };
      if (entity === 'users') update = { ...update, fullName: body.fullName, email: body.email, role: body.role, phone: body.phone };
      if (entity === 'invoices') {
        const subtotal = toNum(body.subtotal), tax = toNum(body.tax), paidAmount = toNum(body.paidAmount);
        const total = subtotal + tax;
        update = { ...update, invoiceNo: body.invoiceNo, client: body.clientId, invoiceDate: body.invoiceDate, dueDate: body.dueDate || null, subtotal, tax, total, paidAmount, balance: Math.max(0, total - paidAmount), paymentStatus: body.paymentStatus, notes: body.notes };
      }
      if (entity === 'payments') update = { ...update, referenceNo: body.referenceNo, client: body.clientId, invoice: body.invoiceId || null, paymentDate: body.paymentDate, amount: toNum(body.amount), mode: body.mode, notes: body.notes };
      if (entity === 'bank') update = { ...update, statementDate: body.statementDate, description: body.description, reference: body.reference, debit: toNum(body.debit), credit: toNum(body.credit), balance: toNum(body.balance), category: body.category, subCategory: body.subCategory, matchedInvoice: body.matchedInvoice || null, matchedClient: body.matchedClient || null, notes: body.notes };
      if (entity === 'stock') {
        const openingQty = toNum(body.openingQty), purchaseQty = toNum(body.purchaseQty), saleQty = toNum(body.saleQty);
        update = { ...update, itemCode: body.itemCode, itemName: body.itemName, category: body.category, unit: body.unit, openingQty, purchaseQty, saleQty, currentQty: openingQty + purchaseQty - saleQty, unitCost: toNum(body.unitCost), salePrice: toNum(body.salePrice), receivedAt: body.receivedAt };
      }
      if (entity === 'notifications') update = { ...update, title: body.title, message: body.message, severity: body.severity, isRead: body.isRead === 'on' };
      const updated = await Model.findByIdAndUpdate(id, update, { new: true });
      await audit(req, { action: 'Update', entityType: entity, entityId: updated._id, before, after: update });
      flash(req, 'success', `${entity} updated successfully.`);
      return res.redirect(back);
    }

    if (action === 'delete') {
      const id = body.id;
      const before = await Model.findById(id).lean();
      await Model.findByIdAndDelete(id);
      await audit(req, { action: 'Delete', entityType: entity, entityId: id, before });
      flash(req, 'success', `${entity} deleted successfully.`);
      return res.redirect(back);
    }

    if (action === 'categorize' && entity === 'bank') {
      const id = body.id;
      const updated = await BankStatement.findByIdAndUpdate(id, {
        category: body.category || 'Uncategorized',
        subCategory: body.subCategory || '',
        matchedInvoice: body.matchedInvoice || null,
        matchedClient: body.matchedClient || null
      }, { new: true });
      await audit(req, { action: 'Update', entityType: 'bank', entityId: id, after: updated });
      flash(req, 'success', 'Bank statement categorized.');
      return res.redirect(back);
    }

    flash(req, 'danger', 'Unsupported action.');
    return res.redirect(back);
  } catch (err) {
    flash(req, 'danger', 'Operation failed.');
    return res.redirect('/app?page=dashboard');
  }
});

app.get('/export/:entity', requireAuth, async (req, res) => {
  try {
    const entity = req.params.entity;
    const models = { clients: Client, users: User, invoices: Invoice, payments: Payment, bank: BankStatement, stock: StockItem, notifications: Notification, audit: AuditLog };
    const Model = models[entity];
    if (!Model) return res.redirect('/app?page=dashboard');
    const docs = await Model.find({}).lean();
    const cols = Object.keys(docs[0] || { noData: '' });
    const csv = [cols.join(','), ...docs.map(d => cols.map(c => JSON.stringify(d[c] ?? '')).join(','))].join('\n');
    await audit(req, { action: 'Export', entityType: entity, entityId: null, after: { count: docs.length } });
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${entity}-${Date.now()}.csv"`);
    return res.send(csv);
  } catch (err) {
    return res.redirect('/app?page=dashboard');
  }
});

app.get('/print/:entity', requireAuth, async (req, res) => {
  await audit(req, { action: 'Print', entityType: req.params.entity, entityId: null });
  return renderApp(req, res);
});

app.get('/app', requireAuth, async (req, res) => {
  try {
    return await renderApp(req, res);
  } catch (err) {
    flash(req, 'danger', 'Unable to load application page.');
    return res.redirect('/app?page=dashboard');
  }
});

app.use((req, res) => {
  if (req.session.user) return res.redirect('/app?page=dashboard');
  return res.redirect('/login');
});

mongoose.connect(MONGODB_URI)
  .then(async () => {
    await seed();
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  })
  .catch(err => {
    console.error('MongoDB connection failed:', err.message || err);
    process.exit(1);
  });
