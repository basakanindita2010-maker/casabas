require('dotenv').config();

const express = require('express');
const session = require('express-session');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const path = require('path');
const fs = require('fs');

const app = express();

const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/financial_suite';
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-this-session-secret-in-production';
const SALT_ROUNDS = 12;
const MAX_UPLOAD_BYTES = 1024 * 1024 * 8;

const STORAGE_DIR = path.join(__dirname, 'storage');
if (!fs.existsSync(STORAGE_DIR)) fs.mkdirSync(STORAGE_DIR, { recursive: true });

const DEFAULT_ADMIN = {
  name: 'Admin User',
  email: 'admin@example.com',
  password: 'Admin@12345',
  role: 'admin',
  isActive: true
};

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

const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true, index: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['admin', 'user'], default: 'user' },
  isActive: { type: Boolean, default: true }
}, { collection: 'users', timestamps: { createdAt: true, updatedAt: false } });

const clientSchema = new mongoose.Schema({
  clientName: { type: String, required: true, trim: true, index: true },
  companyName: { type: String, required: true, trim: true },
  email: { type: String, required: true, trim: true, lowercase: true, unique: true },
  phone: { type: String, required: true, trim: true },
  address: { type: String, required: true, trim: true },
  notes: { type: String, default: '', trim: true },
  tags: [{ type: String, trim: true }],
  status: { type: String, enum: ['Active', 'Inactive'], default: 'Active' },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
}, { collection: 'clients', timestamps: true });

const clientActivitySchema = new mongoose.Schema({
  clientId: { type: mongoose.Schema.Types.ObjectId, ref: 'Client', required: true, index: true },
  action: { type: String, required: true },
  details: { type: String, default: '' },
  meta: { type: Object, default: {} },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
}, { collection: 'client_activities', timestamps: { createdAt: true, updatedAt: false } });

const auditLogSchema = new mongoose.Schema({
  actorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  actorEmail: { type: String, default: '' },
  action: { type: String, required: true },
  entity: { type: String, required: true },
  entityId: { type: String, default: '' },
  details: { type: String, default: '' }
}, { collection: 'audit_logs', timestamps: { createdAt: true, updatedAt: false } });

const documentSchema = new mongoose.Schema({
  title: { type: String, required: true, trim: true, index: true },
  category: { type: String, required: true, trim: true, index: true },
  clientName: { type: String, default: '', trim: true },
  description: { type: String, default: '', trim: true },
  fileName: { type: String, default: '', trim: true },
  mimeType: { type: String, default: '', trim: true },
  fileSize: { type: Number, default: 0 },
  filePath: { type: String, default: '', trim: true },
  storageRef: { type: String, default: '', trim: true },
  downloadCount: { type: Number, default: 0 },
  downloadCountByUser: { type: Object, default: {} },
  uploadedBy: { type: String, default: '' }
}, { collection: 'documents', timestamps: true });

const documentHistorySchema = new mongoose.Schema({
  documentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Document', required: true, index: true },
  action: { type: String, required: true },
  performedBy: { type: String, default: '' },
  details: { type: String, default: '' }
}, { collection: 'document_history', timestamps: { createdAt: true, updatedAt: false } });

const financialStatementSchema = new mongoose.Schema({
  statementType: { type: String, enum: ['Balance Sheet', 'Profit & Loss', 'Cash Flow'], required: true, index: true },
  year: { type: Number, required: true, index: true },
  previousYearData: { type: Object, default: {} },
  data: { type: Object, default: {} },
  computedRatios: { type: Object, default: {} },
  history: [{ action: String, at: Date, notes: String, by: String }],
  createdBy: { type: String, default: '' }
}, { collection: 'financial_statements', timestamps: true });

const User = mongoose.model('User', userSchema);
const Client = mongoose.model('Client', clientSchema);
const ClientActivity = mongoose.model('ClientActivity', clientActivitySchema);
const AuditLog = mongoose.model('AuditLog', auditLogSchema);
const Document = mongoose.model('Document', documentSchema);
const DocumentHistory = mongoose.model('DocumentHistory', documentHistorySchema);
const FinancialStatement = mongoose.model('FinancialStatement', financialStatementSchema);

function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  if (req.session.user.role !== 'admin') return res.status(403).send('Forbidden');
  next();
}

function renderLogin(res, options = {}) {
  return res.render('login', {
    title: 'Financial Suite | Login',
    mode: options.mode || 'login',
    error: options.error || null,
    success: options.success || null,
    mongoStatus: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected',
    serverStatus: 'Running'
  });
}

async function writeAudit(req, action, entity, entityId = '', details = '') {
  try {
    await AuditLog.create({
      actorId: req.session.user?.id,
      actorEmail: req.session.user?.email || '',
      action,
      entity,
      entityId: String(entityId || ''),
      details
    });
  } catch (e) {
    console.error('Audit log error:', e.message);
  }
}

async function seedDefaultAdmin() {
  const existing = await User.findOne({ email: DEFAULT_ADMIN.email });
  if (existing) return;
  const hashed = await bcrypt.hash(DEFAULT_ADMIN.password, SALT_ROUNDS);
  await User.create({ ...DEFAULT_ADMIN, password: hashed });
}

function n(v) {
  const x = Number(v);
  return Number.isFinite(x) ? x : 0;
}

function calcRatios(data = {}) {
  const currentAssets = n(data.currentAssets);
  const inventory = n(data.inventory);
  const currentLiabilities = n(data.currentLiabilities);
  const totalDebt = n(data.totalDebt);
  const equity = n(data.shareholdersEquity);
  const netIncome = n(data.netIncome);
  const ebit = n(data.ebit);
  const depreciation = n(data.depreciation);
  const amortization = n(data.amortization);
  const totalAssets = n(data.totalAssets);
  const totalLiabilities = n(data.totalLiabilities);
  const shares = n(data.weightedAvgShares);
  const capitalEmployed = n(data.capitalEmployed);

  const currentRatio = currentLiabilities ? currentAssets / currentLiabilities : 0;
  const quickRatio = currentLiabilities ? (currentAssets - inventory) / currentLiabilities : 0;
  const debtEquity = equity ? totalDebt / equity : 0;
  const roe = equity ? netIncome / equity : 0;
  const roce = capitalEmployed ? ebit / capitalEmployed : 0;
  const ebitda = ebit + depreciation + amortization;
  const workingCapital = currentAssets - currentLiabilities;
  const netWorth = equity;
  const eps = shares ? netIncome / shares : 0;
  const bookValue = totalAssets - totalLiabilities;

  return {
    currentRatio: Number(currentRatio.toFixed(4)),
    quickRatio: Number(quickRatio.toFixed(4)),
    debtEquity: Number(debtEquity.toFixed(4)),
    roe: Number(roe.toFixed(4)),
    roce: Number(roce.toFixed(4)),
    ebitda: Number(ebitda.toFixed(2)),
    workingCapital: Number(workingCapital.toFixed(2)),
    netWorth: Number(netWorth.toFixed(2)),
    eps: Number(eps.toFixed(4)),
    bookValue: Number(bookValue.toFixed(2))
  };
}

function analysisFromRatios(r) {
  const notes = [];
  if (r.currentRatio < 1) notes.push('Liquidity appears weak; current ratio is below 1.');
  else notes.push('Liquidity is adequate based on current ratio.');

  if (r.quickRatio < 1) notes.push('Quick ratio suggests limited near-term liquid coverage.');
  else notes.push('Quick ratio indicates decent short-term liquidity.');

  if (r.debtEquity > 2) notes.push('Leverage is high; debt/equity ratio exceeds 2.');
  else notes.push('Leverage appears manageable.');

  if (r.roe < 0.1) notes.push('ROE is modest; consider improving profitability.');
  else notes.push('ROE indicates efficient use of equity.');

  if (r.roce < 0.1) notes.push('ROCE is low; capital employed may be under-optimized.');
  else notes.push('ROCE shows healthy capital efficiency.');

  if (r.ebitda < 0) notes.push('Negative EBITDA requires urgent operational review.');
  else notes.push('EBITDA is positive, supporting operating performance.');

  if (r.workingCapital < 0) notes.push('Negative working capital may strain operations.');
  else notes.push('Working capital is positive.');

  if (r.eps < 0) notes.push('EPS is negative; shareholders may be impacted.');
  else notes.push('EPS is positive.');

  if (r.bookValue < 0) notes.push('Book value is negative; liabilities exceed assets.');
  else notes.push('Book value is positive.');

  return notes;
}

function recommendationsFromRatios(r) {
  const recs = [];
  if (r.currentRatio < 1) recs.push('Improve liquidity by increasing current assets or reducing current liabilities.');
  if (r.quickRatio < 1) recs.push('Maintain stronger cash and receivable coverage by optimizing inventory.');
  if (r.debtEquity > 2) recs.push('Reduce leverage by paying down debt or strengthening equity.');
  if (r.roe < 0.1) recs.push('Improve net income to increase return on equity.');
  if (r.roce < 0.1) recs.push('Reallocate capital to higher-return business lines.');
  if (r.ebitda < 0) recs.push('Reduce operating costs and improve gross margin.');
  if (r.workingCapital < 0) recs.push('Tighten cash conversion cycle and improve collections.');
  if (r.eps < 0) recs.push('Focus on earnings improvement and cost discipline.');
  if (r.bookValue < 0) recs.push('Strengthen balance sheet by increasing assets or reducing liabilities.');
  if (!recs.length) recs.push('Financial position looks stable; maintain disciplined growth and regular monitoring.');
  return recs;
}

async function getDashboardStats() {
  return {
    totalUsers: await User.countDocuments(),
    activeUsers: await User.countDocuments({ isActive: true }),
    totalClients: await Client.countDocuments(),
    activeClients: await Client.countDocuments({ status: 'Active' }),
    inactiveClients: await Client.countDocuments({ status: 'Inactive' }),
    totalAuditLogs: await AuditLog.countDocuments(),
    totalActivities: await ClientActivity.countDocuments(),
    totalDocuments: await Document.countDocuments(),
    totalStatements: await FinancialStatement.countDocuments()
  };
}

function normalizeTags(tags) {
  return [...new Set(String(tags || '').split(',').map((t) => t.trim()).filter(Boolean))];
}

function buildStorageRef(filename) {
  return `local://${filename}`;
}

function safeNumber(value, fallback = 1) {
  const num = parseInt(value, 10);
  return Number.isFinite(num) && num > 0 ? num : fallback;
}

function sectionName(section) {
  return ['clients', 'users', 'audit', 'documents', 'finance'].includes(section) ? section : 'clients';
}

function buildNavQuery(base, extra = {}) {
  return new URLSearchParams({ ...base, ...extra }).toString();
}

async function renderApp(req, res, options = {}) {
  const stats = await getDashboardStats();
  const page = safeNumber(req.query.page, 1);
  const limit = 5;

  const q = String(req.query.q || '').trim();
  const status = String(req.query.status || '').trim();
  const tag = String(req.query.tag || '').trim();
  const section = sectionName(String(req.query.section || 'clients').trim());

  const filter = {};
  const and = [];
  if (q) and.push({ $or: [{ clientName: { $regex: q, $options: 'i' } }, { companyName: { $regex: q, $options: 'i' } }, { email: { $regex: q, $options: 'i' } }, { phone: { $regex: q, $options: 'i' } }, { notes: { $regex: q, $options: 'i' } }, { tags: { $regex: q, $options: 'i' } }] });
  if (status) filter.status = status;
  if (tag) filter.tags = { $regex: tag, $options: 'i' };
  if (and.length) filter.$and = and;

  const totalClients = await Client.countDocuments(filter);
  const totalPages = Math.max(Math.ceil(totalClients / limit), 1);
  const clients = await Client.find(filter).sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit).lean();

  const mode = String(req.query.mode || '').trim();
  const editClientId = mode === 'edit' ? String(req.query.clientId || '').trim() : '';
  const viewClientId = mode === 'view' ? String(req.query.clientId || '').trim() : '';

  const editClient = editClientId ? await Client.findById(editClientId).lean() : null;
  const viewClient = viewClientId ? await Client.findById(viewClientId).lean() : null;
  const timelineAction = String(req.query.action || '').trim();
  const viewActivities = viewClient ? await ClientActivity.find({ clientId: viewClient._id, ...(timelineAction ? { action: timelineAction } : {}) }).sort({ createdAt: -1 }).lean() : [];

  const auditAction = String(req.query.auditAction || '').trim();
  const auditEntity = String(req.query.auditEntity || '').trim();
  const auditStart = String(req.query.auditStart || '').trim();
  const auditEnd = String(req.query.auditEnd || '').trim();
  const auditFilter = {};
  if (auditAction) auditFilter.action = auditAction;
  if (auditEntity) auditFilter.entity = auditEntity;
  if (auditStart || auditEnd) {
    auditFilter.createdAt = {};
    if (auditStart) auditFilter.createdAt.$gte = new Date(auditStart);
    if (auditEnd) auditFilter.createdAt.$lte = new Date(`${auditEnd}T23:59:59.999Z`);
  }
  const auditLogs = section === 'audit' ? await AuditLog.find(auditFilter).sort({ createdAt: -1 }).limit(100).lean() : [];

  const users = section === 'users' ? await User.find({}).sort({ createdAt: -1 }).lean() : [];
  const recentActivities = await ClientActivity.find({}).sort({ createdAt: -1 }).limit(8).lean();
  const tagFreqRaw = await Client.aggregate([{ $unwind: '$tags' }, { $group: { _id: '$tags', count: { $sum: 1 } } }, { $sort: { count: -1, _id: 1 } }]);
  const tagCloud = tagFreqRaw.map((t) => ({ tag: t._id, count: t.count, sizeClass: t.count >= 5 ? 'fs-5' : t.count >= 3 ? 'fs-6' : 'fs-7' }));

  const documentQuery = String(req.query.docQ || '').trim();
  const documentCategory = String(req.query.docCategory || '').trim();
  const docActivityFilter = String(req.query.docActivity || '').trim();
  const docOwnerFilter = String(req.query.docOwner || '').trim();
  const docFilter = {};
  const docAnd = [];
  if (documentQuery) docAnd.push({ $or: [{ title: { $regex: documentQuery, $options: 'i' } }, { category: { $regex: documentQuery, $options: 'i' } }, { clientName: { $regex: documentQuery, $options: 'i' } }, { description: { $regex: documentQuery, $options: 'i' } }, { fileName: { $regex: documentQuery, $options: 'i' } }] });
  if (documentCategory) docFilter.category = documentCategory;
  if (docOwnerFilter) docFilter.uploadedBy = docOwnerFilter;
  if (docAnd.length) docFilter.$and = docAnd;

  const documents = section === 'documents' ? await Document.find(docFilter).sort({ createdAt: -1 }).limit(50).lean() : [];
  const documentCategories = section === 'documents' ? await Document.distinct('category') : [];
  const documentOwners = section === 'documents' ? await Document.distinct('uploadedBy') : [];
  const documentHistory = section === 'documents' ? await DocumentHistory.find({ ...(docActivityFilter ? { action: docActivityFilter } : {}) }).sort({ createdAt: -1 }).limit(50).lean() : [];
  const documentTimeline = section === 'documents' ? await DocumentHistory.find({ documentId: { $in: documents.map((d) => d._id) } }).sort({ createdAt: -1 }).limit(50).lean() : [];

  const fsQuery = String(req.query.fsQ || '').trim();
  const fsType = String(req.query.fsType || '').trim();
  const fsHistory = String(req.query.fsHistory || '').trim();
  const fsFilter = {};
  if (fsType) fsFilter.statementType = fsType;
  if (fsQuery) {
    fsFilter.$or = [
      { statementType: { $regex: fsQuery, $options: 'i' } },
      { history: { $elemMatch: { notes: { $regex: fsQuery, $options: 'i' } } } }
    ];
  }

  let financialStatements = [];
  if (section === 'finance') {
    financialStatements = await FinancialStatement.find(fsFilter).sort({ year: -1, createdAt: -1 }).lean();
    if (fsHistory) {
      financialStatements = financialStatements.map((s) => ({
        ...s,
        history: (s.history || []).filter((h) => (h.notes || '').toLowerCase().includes(fsHistory.toLowerCase()))
      }));
    }
  }

  const combinedFeed = await Promise.all([
    ClientActivity.find({}).sort({ createdAt: -1 }).limit(5).lean(),
    DocumentHistory.find({}).sort({ createdAt: -1 }).limit(5).lean()
  ]).then(([ca, dh]) => [
    ...ca.map((x) => ({ kind: 'client', at: x.createdAt, text: `${x.action}: ${x.details}` })),
    ...dh.map((x) => ({ kind: 'document', at: x.createdAt, text: `${x.action}: ${x.details}` }))
  ].sort((a, b) => new Date(b.at) - new Date(a.at)).slice(0, 10));

  const recommendations = section === 'finance' && financialStatements.length
    ? recommendationsFromRatios(financialStatements[0].computedRatios || {})
    : [];

  const analysis = section === 'finance' && financialStatements.length
    ? analysisFromRatios(financialStatements[0].computedRatios || {})
    : [];

  return res.render('app', {
    title: 'Financial Suite | Dashboard',
    user: req.session.user,
    stats,
    clients, users, auditLogs, recentActivities, tagCloud,
    documents, documentCategories, documentOwners, documentHistory, documentTimeline,
    financialStatements, combinedFeed, recommendations, analysis,
    q, status, tag, page, totalPages, editClient, editMode: !!editClient, viewClient, viewMode: !!viewClient, viewActivities,
    timelineAction, auditAction, auditEntity, auditStart, auditEnd, docActivityFilter, docOwnerFilter,
    fsQuery, fsType, fsHistory,
    section,
    navClientsUrl: `/app?${buildNavQuery({ section: 'clients' })}`,
    navUsersUrl: `/app?${buildNavQuery({ section: 'users' })}`,
    navAuditUrl: `/app?${buildNavQuery({ section: 'audit' })}`,
    navDocumentsUrl: `/app?${buildNavQuery({ section: 'documents' })}`,
    navFinanceUrl: `/app?${buildNavQuery({ section: 'finance' })}`,
    error: options.error || null,
    success: options.success || null,
    toast: options.toast || null,
    mongoStatus: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected',
    serverStatus: 'Running'
  });
}

function parseMultipartFields(req) {
  return new Promise((resolve, reject) => {
    const contentType = req.headers['content-type'] || '';
    const boundaryMatch = contentType.match(/boundary=(.*)$/i);
    if (!boundaryMatch) return reject(new Error('Invalid multipart form data'));
    const boundary = `--${boundaryMatch[1]}`;
    const chunks = [];
    let total = 0;
    req.on('data', (chunk) => { total += chunk.length; if (total > MAX_UPLOAD_BYTES) { reject(new Error('File too large')); req.destroy(); return; } chunks.push(chunk); });
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('binary');
      const parts = body.split(boundary).filter((p) => p.includes('Content-Disposition'));
      const fields = {}; let file = null;
      for (const part of parts) {
        const headerEnd = part.indexOf('\r\n\r\n'); if (headerEnd === -1) continue;
        const headers = part.slice(0, headerEnd);
        const value = part.slice(headerEnd + 4).replace(/\r\n--$/, '').replace(/\r\n$/, '');
        const nameMatch = headers.match(/name="([^"]+)"/i); if (!nameMatch) continue;
        const fieldName = nameMatch[1];
        const filenameMatch = headers.match(/filename="([^"]+)"/i);
        const mimeMatch = headers.match(/Content-Type:\s*([^\r\n]+)/i);
        if (filenameMatch) file = { fieldName, filename: filenameMatch[1].trim(), mimeType: (mimeMatch ? mimeMatch[1].trim().toLowerCase() : ''), buffer: Buffer.from(value, 'binary') };
        else fields[fieldName] = value;
      }
      resolve({ fields, file });
    });
    req.on('error', reject);
  });
}

app.get('/', (req, res) => req.session.user ? res.redirect('/app') : res.redirect('/login'));
app.get('/login', (req, res) => { if (req.session.user) return res.redirect('/app'); renderLogin(res, { mode: 'login' }); });
app.get('/register', (req, res) => { if (req.session.user) return res.redirect('/app'); renderLogin(res, { mode: 'register' }); });

app.post('/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return renderLogin(res, { mode: 'register', error: 'All fields are required.' });
    const normalizedEmail = String(email).trim().toLowerCase();
    if (await User.findOne({ email: normalizedEmail })) return renderLogin(res, { mode: 'register', error: 'This email is already registered.' });
    const hashed = await bcrypt.hash(password, SALT_ROUNDS);
    const user = await User.create({ name: String(name).trim(), email: normalizedEmail, password: hashed, role: 'user', isActive: true });
    req.session.user = { id: user._id.toString(), name: user.name, email: user.email, role: user.role };
    await writeAudit(req, 'REGISTER', 'user', user._id, 'User registered');
    return res.redirect('/app');
  } catch (error) { console.error(error); return renderLogin(res, { mode: 'register', error: 'Registration failed.' }); }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return renderLogin(res, { mode: 'login', error: 'Email and password are required.' });
    const normalizedEmail = String(email).trim().toLowerCase();
    const user = await User.findOne({ email: normalizedEmail });
    if (!user) return renderLogin(res, { mode: 'login', error: 'Invalid email or password.' });
    if (!user.isActive) return renderLogin(res, { mode: 'login', error: 'Your account is inactive.' });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return renderLogin(res, { mode: 'login', error: 'Invalid email or password.' });
    req.session.user = { id: user._id.toString(), name: user.name, email: user.email, role: user.role };
    await writeAudit(req, 'LOGIN', 'user', user._id, 'User logged in');
    return res.redirect('/app');
  } catch (error) { console.error(error); return renderLogin(res, { mode: 'login', error: 'Login failed.' }); }
});

app.get('/app', requireAuth, async (req, res) => renderApp(req, res));

app.post('/financial-statements', requireAuth, async (req, res) => {
  try {
    const { statementType, year, previousYearData, data } = req.body;
    if (!statementType || !year) return renderApp(req, res, { error: 'Statement type and year are required.' });
    const parsedPrev = previousYearData ? JSON.parse(previousYearData) : {};
    const parsedData = data ? JSON.parse(data) : {};
    const computedRatios = calcRatios(parsedData);
    const stmt = await FinancialStatement.create({ statementType, year: Number(year), previousYearData: parsedPrev, data: parsedData, computedRatios, history: [{ action: 'created', at: new Date(), notes: 'Financial statement created', by: req.session.user.email }], createdBy: req.session.user.email });
    await writeAudit(req, 'CREATE', 'financial_statement', stmt._id, `${statementType} for year ${year}`);
    return res.redirect('/app?section=finance');
  } catch (error) { console.error(error); return renderApp(req, res, { error: 'Unable to save financial statement.' }); }
});

app.post('/financial-statements/:id/recalculate', requireAuth, async (req, res) => {
  try {
    const { data, previousYearData, notes } = req.body;
    const stmt = await FinancialStatement.findById(req.params.id);
    if (!stmt) return res.redirect('/app?section=finance');
    const parsedData = data ? JSON.parse(data) : stmt.data || {};
    const parsedPrev = previousYearData ? JSON.parse(previousYearData) : stmt.previousYearData || {};
    stmt.previousYearData = parsedPrev;
    stmt.data = parsedData;
    stmt.computedRatios = calcRatios(parsedData);
    stmt.history = stmt.history || [];
    stmt.history.push({ action: 'recalculated', at: new Date(), notes: String(notes || 'Ratios recalculated'), by: req.session.user.email });
    await stmt.save();
    await writeAudit(req, 'UPDATE', 'financial_statement', stmt._id, 'Financial ratios recalculated');
    return res.redirect('/app?section=finance');
  } catch (error) { console.error(error); return renderApp(req, res, { error: 'Unable to recalculate financial ratios.' }); }
});

app.post('/financial-statements/:id/history', requireAuth, async (req, res) => {
  try {
    const { notes } = req.body;
    const stmt = await FinancialStatement.findById(req.params.id);
    if (!stmt) return res.redirect('/app?section=finance');
    stmt.history = stmt.history || [];
    stmt.history.push({ action: 'updated', at: new Date(), notes: String(notes || 'Updated'), by: req.session.user.email });
    await stmt.save();
    await writeAudit(req, 'UPDATE', 'financial_statement', stmt._id, 'Financial statement history updated');
    return res.redirect('/app?section=finance');
  } catch (error) { console.error(error); return res.redirect('/app?section=finance'); }
});

app.post('/clients', requireAuth, async (req, res) => {
  try {
    const { clientName, companyName, email, phone, address, notes, tags, status } = req.body;
    if (!clientName || !companyName || !email || !phone || !address) return renderApp(req, res, { error: 'All client fields are required.' });
    const normalizedEmail = String(email).trim().toLowerCase();
    if (await Client.findOne({ email: normalizedEmail })) return renderApp(req, res, { error: 'Duplicate client email found.' });
    const client = await Client.create({ clientName: String(clientName).trim(), companyName: String(companyName).trim(), email: normalizedEmail, phone: String(phone).trim(), address: String(address).trim(), notes: String(notes || '').trim(), tags: normalizeTags(tags), status: status === 'Inactive' ? 'Inactive' : 'Active', createdBy: req.session.user.id });
    await ClientActivity.create({ clientId: client._id, action: 'Created', details: 'Client created', createdBy: req.session.user.id });
    await writeAudit(req, 'CREATE', 'client', client._id, 'Client created');
    return res.redirect('/app?section=clients');
  } catch (error) { console.error(error); return renderApp(req, res, { error: 'Unable to add client.' }); }
});

app.post('/documents/upload', requireAuth, async (req, res) => {
  try {
    const { fields, file } = await parseMultipartFields(req);
    if (!fields.title || !fields.category) return renderApp(req, res, { error: 'Document title and category are required.' });
    if (!file) return renderApp(req, res, { error: 'Please choose a file for upload.' });
    const allowed = new Set(['application/pdf', 'image/png', 'image/jpeg', 'text/plain', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']);
    if (!allowed.has(file.mimeType)) return renderApp(req, res, { error: 'File type not allowed.' });

    const safeName = `${Date.now()}_${path.basename(file.filename)}`;
    const filePath = path.join(STORAGE_DIR, safeName);
    fs.writeFileSync(filePath, file.buffer);

    const doc = await Document.create({
      title: String(fields.title).trim(),
      category: String(fields.category).trim(),
      clientName: String(fields.clientName || '').trim(),
      description: String(fields.description || '').trim(),
      fileName: safeName,
      mimeType: file.mimeType,
      fileSize: file.buffer.length,
      filePath,
      storageRef: buildStorageRef(safeName),
      uploadedBy: req.session.user.email
    });

    await DocumentHistory.create({ documentId: doc._id, action: 'uploaded', performedBy: req.session.user.email, details: 'Document uploaded with file reference' });
    await writeAudit(req, 'CREATE', 'document', doc._id, 'Document uploaded');
    return res.redirect('/app?section=documents');
  } catch (error) { console.error(error); return renderApp(req, res, { error: error.message === 'File too large' ? 'File too large.' : 'Unable to upload document.' }); }
});

app.get('/documents/:id/download', requireAuth, async (req, res) => {
  try {
    const doc = await Document.findById(req.params.id);
    if (!doc) return res.redirect('/app?section=documents');
    doc.downloadCount += 1;
    doc.downloadCountByUser = doc.downloadCountByUser || {};
    doc.downloadCountByUser[req.session.user.email] = (doc.downloadCountByUser[req.session.user.email] || 0) + 1;
    await doc.save();
    await DocumentHistory.create({ documentId: doc._id, action: 'downloaded', performedBy: req.session.user.email, details: `Downloaded by ${req.session.user.email}` });
    await writeAudit(req, 'DOWNLOAD', 'document', doc._id, 'Document downloaded');
    if (doc.filePath && fs.existsSync(doc.filePath)) return res.download(doc.filePath, doc.fileName || path.basename(doc.filePath));
    return res.redirect('/app?section=documents');
  } catch (error) { console.error(error); return res.redirect('/app?section=documents'); }
});

app.post('/documents/:id/edit', requireAuth, async (req, res) => {
  try {
    const { fields, file } = await parseMultipartFields(req);
    const doc = await Document.findById(req.params.id);
    if (!doc) return res.redirect('/app?section=documents');
    if (!fields.title || !fields.category) return res.redirect('/app?section=documents');

    if (file) {
      const allowed = new Set(['application/pdf', 'image/png', 'image/jpeg', 'text/plain', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']);
      if (!allowed.has(file.mimeType)) return renderApp(req, res, { error: 'File type not allowed.' });
      const safeName = `${Date.now()}_${path.basename(file.filename)}`;
      const filePath = path.join(STORAGE_DIR, safeName);
      fs.writeFileSync(filePath, file.buffer);
      if (doc.filePath && fs.existsSync(doc.filePath)) fs.unlinkSync(doc.filePath);
      doc.fileName = safeName;
      doc.filePath = filePath;
      doc.storageRef = buildStorageRef(safeName);
      doc.mimeType = file.mimeType;
      doc.fileSize = file.buffer.length;
    }

    doc.title = String(fields.title).trim();
    doc.category = String(fields.category).trim();
    doc.clientName = String(fields.clientName || '').trim();
    doc.description = String(fields.description || '').trim();
    await doc.save();
    await DocumentHistory.create({ documentId: doc._id, action: 'updated', performedBy: req.session.user.email, details: 'Document updated with file reference' });
    await writeAudit(req, 'UPDATE', 'document', req.params.id, 'Document updated');
    return res.redirect('/app?section=documents');
  } catch (error) { console.error(error); return res.redirect('/app?section=documents'); }
});

app.get('/clients/:id/view', requireAuth, async (req, res) => {
  return res.redirect(`/app?section=clients&mode=view&clientId=${req.params.id}&page=${encodeURIComponent(req.query.page || 1)}&q=${encodeURIComponent(req.query.q || '')}&status=${encodeURIComponent(req.query.status || '')}&tag=${encodeURIComponent(req.query.tag || '')}`);
});

app.post('/clients/:id/edit', requireAuth, async (req, res) => {
  try {
    const { clientName, companyName, email, phone, address, notes, tags, status } = req.body;
    const normalizedEmail = String(email).trim().toLowerCase();
    const duplicate = await Client.findOne({ email: normalizedEmail, _id: { $ne: req.params.id } });
    if (duplicate) return renderApp(req, res, { error: 'Duplicate client email found.' });
    await Client.findByIdAndUpdate(req.params.id, { clientName: String(clientName).trim(), companyName: String(companyName).trim(), email: normalizedEmail, phone: String(phone).trim(), address: String(address).trim(), notes: String(notes || '').trim(), tags: normalizeTags(tags), status: status === 'Inactive' ? 'Inactive' : 'Active' });
    await ClientActivity.create({ clientId: req.params.id, action: 'Updated', details: 'Client updated', createdBy: req.session.user.id });
    await writeAudit(req, 'UPDATE', 'client', req.params.id, 'Client updated');
    return res.redirect('/app?section=clients');
  } catch (error) { console.error(error); return renderApp(req, res, { error: 'Unable to edit client.' }); }
});

app.post('/clients/:id/delete', requireAuth, async (req, res) => {
  try {
    await Client.findByIdAndDelete(req.params.id);
    await writeAudit(req, 'DELETE', 'client', req.params.id, 'Client deleted');
    return res.redirect('/app?section=clients');
  } catch (error) { console.error(error); return renderApp(req, res, { error: 'Unable to delete client.' }); }
});

app.post('/logout', (req, res) => { req.session.destroy(() => { res.clearCookie('connect.sid'); res.redirect('/login'); }); });
app.get('/health', (req, res) => res.json({ status: 'ok', server: 'running', mongo: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected' }));
app.use((req, res) => { if (req.session.user) return res.status(404).send('Page not found'); return res.redirect('/login'); });

async function startServer() {
  try {
    await mongoose.connect(MONGODB_URI, { dbName: 'financial_suite' });
    await seedDefaultAdmin();
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  } catch (error) {
    console.error('Startup error:', error);
    process.exit(1);
  }
}

startServer();
