require('dotenv').config();

const express = require('express');
const session = require('express-session');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const OpenAI = require('openai');
const puppeteer = require('puppeteer');
const ExcelJS = require('exceljs');
const archiver = require('archiver');

const app = express();

const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/financial_suite';
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-this-session-secret-in-production';
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || '';
const OPENAI_MODEL = process.env.OPENAI_MODEL || 'gpt-4o-mini';
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

const allowedMimeTypes = new Set([
  'application/pdf',
  'image/png',
  'image/jpeg',
  'text/plain',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
]);

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_UPLOAD_BYTES },
  fileFilter: (req, file, cb) => {
    if (!allowedMimeTypes.has(file.mimetype)) return cb(new Error('File type not allowed.'));
    cb(null, true);
  }
});

const openai = OPENAI_API_KEY ? new OpenAI({ apiKey: OPENAI_API_KEY }) : null;

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
      secure: process.env.NODE_ENV === 'production',
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

const advisorySchema = new mongoose.Schema({
  businessName: { type: String, required: true, trim: true },
  industry: { type: String, required: true, trim: true },
  annualTurnover: { type: Number, required: true },
  ebitda: { type: Number, required: true },
  existingDebt: { type: Number, required: true },
  workingCapitalCycleDays: { type: Number, default: 0 },
  collateralValue: { type: Number, default: 0 },
  ownerCreditScore: { type: Number, default: 0 },
  loanAmountRequired: { type: Number, required: true },
  loanPurpose: { type: String, required: true, trim: true },
  bankPreference: { type: String, default: 'Any', trim: true },
  currentAssets: { type: Number, default: 0 },
  currentLiabilities: { type: Number, default: 0 },
  notes: { type: String, default: '', trim: true },
  createdBy: { type: String, default: '' },
  readiness: {
    score: { type: Number, default: 0 },
    band: { type: String, default: 'Low' },
    recommendationStatus: { type: String, default: 'Review' }
  },
  lenderMatrix: [{
    bankName: String,
    score: Number,
    dscrThreshold: Number,
    fit: String,
    verdict: String
  }],
  bankComparison: [{
    bankName: String,
    score: Number,
    fit: String,
    verdict: String
  }],
  recommendations: {
    executiveSummary: { type: String, default: '' },
    strengths: [{ type: String }],
    weaknesses: [{ type: String }],
    risks: [{ type: String }],
    actions: [{ type: String }]
  }
}, { collection: 'sme_lending_advisories', timestamps: true });

const loanApplicationSchema = new mongoose.Schema({
  applicantName: { type: String, required: true, trim: true },
  applicantEmail: { type: String, required: true, trim: true, lowercase: true },
  applicantPhone: { type: String, required: true, trim: true },
  applicantCompany: { type: String, default: '', trim: true },
  loanAmountRequested: { type: Number, required: true },
  loanPurpose: { type: String, required: true, trim: true },
  tenureMonths: { type: Number, required: true },
  annualInterestRate: { type: Number, required: true },
  monthlyIncome: { type: Number, required: true },
  monthlyExistingObligations: { type: Number, required: true },
  monthlyOperatingExpenses: { type: Number, required: true },
  collateralValue: { type: Number, default: 0 },
  creditScore: { type: Number, default: 0 },
  bankName: { type: String, default: 'General', trim: true },
  currentAssets: { type: Number, default: 0 },
  currentLiabilities: { type: Number, default: 0 },
  ebitda: { type: Number, default: 0 },
  debtServiceAnnual: { type: Number, default: 0 },
  emiMonthly: { type: Number, default: 0 },
  notes: { type: String, default: '', trim: true },
  createdBy: { type: String, default: '' },
  scoring: {
    borrowerProfileScore: { type: Number, default: 0 },
    bankWiseRating: { type: String, default: 'NR' },
    riskBand: { type: String, default: 'Unknown' },
    approvalStatus: { type: String, default: 'Pending' }
  },
  repaymentSchedule: [{
    month: Number,
    openingBalance: Number,
    emi: Number,
    interest: Number,
    principal: Number,
    closingBalance: Number
  }]
}, { collection: 'loan_applications', timestamps: true });

const financialStatementSchema = new mongoose.Schema({
  statementType: { type: String, enum: ['Balance Sheet', 'Profit & Loss', 'Cash Flow', 'Loan Analysis'], required: true, index: true },
  year: { type: Number, required: true, index: true },
  previousYearData: { type: Object, default: {} },
  data: { type: Object, default: {} },
  computedRatios: { type: Object, default: {} },
  financialHealthScore: { type: Number, default: 0 },
  loanMetrics: {
    dscr: { type: Number, default: 0 },
    emiCapacity: { type: Number, default: 0 },
    loanEligibility: { type: Number, default: 0 },
    interestCoverage: { type: Number, default: 0 },
    bankRating: { type: String, default: 'NR' },
    eligibleLoanAmount: { type: Number, default: 0 },
    recommendedEMI: { type: Number, default: 0 }
  },
  aiInsights: {
    executiveSummary: { type: String, default: '' },
    strengths: [{ type: String }],
    weaknesses: [{ type: String }],
    riskAnalysis: [{ type: String }],
    recommendations: [{ type: String }]
  },
  history: [{ action: String, at: Date, notes: String, by: String }],
  createdBy: { type: String, default: '' }
}, { collection: 'financial_statements', timestamps: true });

const User = mongoose.model('User', userSchema);
const Client = mongoose.model('Client', clientSchema);
const ClientActivity = mongoose.model('ClientActivity', clientActivitySchema);
const AuditLog = mongoose.model('AuditLog', auditLogSchema);
const Document = mongoose.model('Document', documentSchema);
const DocumentHistory = mongoose.model('DocumentHistory', documentHistorySchema);
const SMEAdvisory = mongoose.model('SMEAdvisory', advisorySchema);
const LoanApplication = mongoose.model('LoanApplication', loanApplicationSchema);
const FinancialStatement = mongoose.model('FinancialStatement', financialStatementSchema);

function requireAuth(req, res, next) { if (!req.session.user) return res.redirect('/login'); next(); }
function renderLogin(res, options = {}) { return res.render('login', { title: 'Financial Suite | Login', mode: options.mode || 'login', error: options.error || null, success: options.success || null, mongoStatus: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected', serverStatus: 'Running' }); }
async function writeAudit(req, action, entity, entityId = '', details = '') { try { await AuditLog.create({ actorId: req.session.user?.id, actorEmail: req.session.user?.email || '', action, entity, entityId: String(entityId || ''), details }); } catch (e) { console.error('Audit log error:', e.message); } }
async function seedDefaultAdmin() { const existing = await User.findOne({ email: DEFAULT_ADMIN.email }); if (existing) return; const hashed = await bcrypt.hash(DEFAULT_ADMIN.password, SALT_ROUNDS); await User.create({ ...DEFAULT_ADMIN, password: hashed }); }
function n(v) { const x = Number(v); return Number.isFinite(x) ? x : 0; }
function clamp(v, min, max) { return Math.max(min, Math.min(max, v)); }

function readinessBand(score) { if (score >= 80) return 'Ready'; if (score >= 60) return 'Near Ready'; if (score >= 40) return 'Monitor'; return 'High Risk'; }
function bankComparisonFromAdvisory(app, readinessScore) { const banks = [{ bankName: 'SBI', min: 65 }, { bankName: 'HDFC', min: 72 }, { bankName: 'ICICI', min: 70 }, { bankName: 'Axis', min: 68 }]; return banks.map((b) => ({ bankName: b.bankName, score: clamp(Math.round(readinessScore), 0, 100), fit: readinessScore >= b.min ? 'Good Fit' : 'Limited Fit', verdict: readinessScore >= b.min ? 'Proceed' : 'Review' })); }
function lenderMatrixFromAdvisory(app, readinessScore) { const banks = [{ bankName: 'SBI', dscrThreshold: 1.25, min: 65 }, { bankName: 'HDFC', dscrThreshold: 1.35, min: 72 }, { bankName: 'ICICI', dscrThreshold: 1.3, min: 70 }, { bankName: 'Axis', dscrThreshold: 1.28, min: 68 }]; return banks.map((b) => ({ bankName: b.bankName, score: clamp(Math.round(readinessScore), 0, 100), dscrThreshold: b.dscrThreshold, fit: readinessScore >= b.min ? 'Good Fit' : 'Limited Fit', verdict: readinessScore >= b.min ? 'Proceed' : 'Review' })); }
function advisoryRecommendations(app, readinessScore, bankComparison) { const strengths = []; const weaknesses = []; const risks = []; const actions = []; if (readinessScore >= 80) strengths.push('Business is lending-ready based on the current profile.'); if (n(app.ebitda) > 0) strengths.push('EBITDA is positive.'); if (n(app.collateralValue) >= n(app.loanAmountRequired)) strengths.push('Collateral coverage is adequate.'); if (n(app.ownerCreditScore) >= 750) strengths.push('Owner credit profile is strong.'); if (n(app.ebitda) <= 0) weaknesses.push('EBITDA is weak or negative.'); if (n(app.existingDebt) > n(app.annualTurnover) * 0.8) weaknesses.push('Debt burden is high.'); if (n(app.workingCapitalCycleDays) > 90) weaknesses.push('Working capital cycle is stretched.'); if (readinessScore < 60) risks.push('Bank rejection risk is elevated.'); if (n(app.loanAmountRequired) > n(app.annualTurnover) * 0.5) risks.push('Requested amount may be aggressive versus turnover.'); if (n(app.currentLiabilities) > n(app.currentAssets)) risks.push('Liquidity risk is present.'); const topBank = bankComparison.find((b) => b.verdict === 'Proceed') || bankComparison[0]; actions.push(`Focus on ${topBank.bankName} as the primary lender option.`); actions.push('Improve DSCR and reduce working capital cycle where possible.'); actions.push('Prepare a lender note with cash flow summary and collateral details.'); return { strengths, weaknesses, risks, actions }; }
async function openaiRecommendations(payload) { if (!openai) return { executiveSummary: `SME readiness score: ${payload.readinessScore}/100.`, strengths: payload.strengths, weaknesses: payload.weaknesses, risks: payload.risks, actions: payload.actions }; try { const prompt = `You are an SME lending advisor. Business: ${JSON.stringify(payload.advisoryInput, null, 2)} Readiness score: ${payload.readinessScore} Lender matrix: ${JSON.stringify(payload.lenderMatrix || [], null, 2)} Bank comparison: ${JSON.stringify(payload.bankComparison, null, 2)} Return JSON only: { "executiveSummary": "string", "strengths": ["string"], "weaknesses": ["string"], "risks": ["string"], "actions": ["string"] }`; const completion = await openai.chat.completions.create({ model: OPENAI_MODEL, messages: [{ role: 'system', content: 'Return only valid JSON for SME lending advisory.' }, { role: 'user', content: prompt }], temperature: 0.35 }); const parsed = JSON.parse(completion.choices?.[0]?.message?.content || '{}'); return { executiveSummary: parsed.executiveSummary || `SME readiness score: ${payload.readinessScore}/100.`, strengths: Array.isArray(parsed.strengths) ? parsed.strengths : payload.strengths, weaknesses: Array.isArray(parsed.weaknesses) ? parsed.weaknesses : payload.weaknesses, risks: Array.isArray(parsed.risks) ? parsed.risks : payload.risks, actions: Array.isArray(parsed.actions) ? parsed.actions : payload.actions }; } catch { return { executiveSummary: `SME readiness score: ${payload.readinessScore}/100.`, strengths: payload.strengths, weaknesses: payload.weaknesses, risks: payload.risks, actions: payload.actions }; } }

function smeAdvisoryToPdfHtml(item) {
  const bc = item.bankComparison || [];
  const lm = item.lenderMatrix || [];
  const rec = item.recommendations || {};
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>SME Advisory</title><style>@page{size:A4;margin:18mm}body{font-family:Arial;margin:24px;color:#1f2937}.card{border:1px solid #e5e7eb;border-radius:12px;padding:16px;margin-bottom:16px}table{width:100%;border-collapse:collapse}th,td{border:1px solid #e5e7eb;padding:8px;font-size:12px}th{background:#eff6ff}</style></head><body><h1>SME Lending Advisory Report</h1><div class="card"><p><strong>Business:</strong> ${item.businessName}</p><p><strong>Industry:</strong> ${item.industry}</p><p><strong>Readiness Score:</strong> ${item.readiness.score}/100</p><p><strong>Band:</strong> ${item.readiness.band}</p><p><strong>Status:</strong> ${item.readiness.recommendationStatus}</p><p><strong>Summary:</strong> ${rec.executiveSummary || ''}</p></div><div class="card"><h2>Summary Cover</h2><p>This package contains one PDF per advisory, one XLSX per advisory, a master index, and a summary cover sheet.</p></div><div class="card"><h2>Lender Comparison Matrix</h2><table><thead><tr><th>Bank</th><th>Score</th><th>DSCR Threshold</th><th>Fit</th><th>Verdict</th></tr></thead><tbody>${lm.map((b) => `<tr><td>${b.bankName}</td><td>${b.score}</td><td>${b.dscrThreshold}</td><td>${b.fit}</td><td>${b.verdict}</td></tr>`).join('')}</tbody></table></div><div class="card"><h2>Bank Comparison</h2><table><thead><tr><th>Bank</th><th>Score</th><th>Fit</th><th>Verdict</th></tr></thead><tbody>${bc.map((b) => `<tr><td>${b.bankName}</td><td>${b.score}</td><td>${b.fit}</td><td>${b.verdict}</td></tr>`).join('')}</tbody></table></div></body></html>`;
}

function smeAdvisoryWorkbook(item) {
  const wb = new ExcelJS.Workbook();
  wb.creator = 'Financial Suite SaaS';
  const ws1 = wb.addWorksheet('SME Summary');
  ws1.columns = [{ header: 'Field', key: 'field', width: 30 }, { header: 'Value', key: 'value', width: 40 }];
  [['Business Name', item.businessName],['Industry', item.industry],['Annual Turnover', item.annualTurnover],['EBITDA', item.ebitda],['Existing Debt', item.existingDebt],['Working Capital Cycle Days', item.workingCapitalCycleDays],['Collateral Value', item.collateralValue],['Owner Credit Score', item.ownerCreditScore],['Loan Amount Required', item.loanAmountRequired],['Loan Purpose', item.loanPurpose],['Bank Preference', item.bankPreference],['Readiness Score', item.readiness.score],['Readiness Band', item.readiness.band],['Recommendation Status', item.readiness.recommendationStatus]].forEach(([field, value]) => ws1.addRow({ field, value }));
  const ws2 = wb.addWorksheet('Lender Matrix');
  ws2.columns = [{ header: 'Bank', key: 'bankName', width: 16 }, { header: 'Score', key: 'score', width: 10 }, { header: 'DSCR Threshold', key: 'dscrThreshold', width: 15 }, { header: 'Fit', key: 'fit', width: 14 }, { header: 'Verdict', key: 'verdict', width: 12 }];
  item.lenderMatrix.forEach((b) => ws2.addRow(b));
  const ws3 = wb.addWorksheet('Bank Comparison');
  ws3.columns = [{ header: 'Bank', key: 'bankName', width: 16 }, { header: 'Score', key: 'score', width: 10 }, { header: 'Fit', key: 'fit', width: 14 }, { header: 'Verdict', key: 'verdict', width: 12 }];
  item.bankComparison.forEach((b) => ws3.addRow(b));
  const ws4 = wb.addWorksheet('Advisory Notes');
  ws4.columns = [{ header: 'Section', key: 'section', width: 18 }, { header: 'Note', key: 'note', width: 80 }];
  (item.recommendations.strengths || []).forEach((s) => ws4.addRow({ section: 'Strength', note: s }));
  (item.recommendations.weaknesses || []).forEach((s) => ws4.addRow({ section: 'Weakness', note: s }));
  (item.recommendations.risks || []).forEach((s) => ws4.addRow({ section: 'Risk', note: s }));
  (item.recommendations.actions || []).forEach((s) => ws4.addRow({ section: 'Action', note: s }));
  return wb;
}

async function buildBatchPackageBuffer(items) {
  const archive = archiver('zip', { zlib: { level: 9 } });
  const chunks = [];
  archive.on('data', (c) => chunks.push(c));

  const summaryHtml = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Batch Summary</title><style>@page{size:A4;margin:18mm}body{font-family:Arial;margin:24px}h1{color:#0f172a}table{width:100%;border-collapse:collapse}th,td{border:1px solid #e5e7eb;padding:8px;font-size:12px}th{background:#eff6ff}</style></head><body><h1>SME Advisory Batch Summary</h1><p>Total Advisories: ${items.length}</p><table><thead><tr><th>Business</th><th>Industry</th><th>Score</th><th>Band</th><th>Status</th></tr></thead><tbody>${items.map((i) => `<tr><td>${i.businessName}</td><td>${i.industry}</td><td>${i.readiness?.score || 0}</td><td>${i.readiness?.band || ''}</td><td>${i.readiness?.recommendationStatus || ''}</td></tr>`).join('')}</tbody></table></body></html>`;
  const sb = await puppeteer.launch({ headless: 'new', args: ['--no-sandbox', '--disable-setuid-sandbox'] });
  const sp = await sb.newPage();
  await sp.setContent(summaryHtml, { waitUntil: 'networkidle0' });
  const summaryPdf = await sp.pdf({ format: 'A4', printBackground: true, preferCSSPageSize: true });
  await sb.close();
  archive.append(summaryPdf, { name: 'Summary_Cover.pdf' });

  const indexWb = new ExcelJS.Workbook();
  const ws = indexWb.addWorksheet('Index');
  ws.columns = [{ header: 'Business', key: 'business', width: 24 }, { header: 'Industry', key: 'industry', width: 18 }, { header: 'File PDF', key: 'pdf', width: 28 }, { header: 'File XLSX', key: 'xlsx', width: 28 }];

  for (const item of items) {
    const pdfName = `${item.businessName.replace(/\s+/g, '_')}.pdf`;
    const xlsxName = `${item.businessName.replace(/\s+/g, '_')}.xlsx`;

    ws.addRow({ business: item.businessName, industry: item.industry, pdf: pdfName, xlsx: xlsxName });

    const pdfBrowser = await puppeteer.launch({ headless: 'new', args: ['--no-sandbox', '--disable-setuid-sandbox'] });
    const pdfPage = await pdfBrowser.newPage();
    await pdfPage.setContent(smeAdvisoryToPdfHtml(item), { waitUntil: 'networkidle0' });
    const pdfBuffer = await pdfPage.pdf({ format: 'A4', printBackground: true, preferCSSPageSize: true });
    await pdfBrowser.close();
    archive.append(pdfBuffer, { name: pdfName });

    const xwb = smeAdvisoryWorkbook(item);
    const xbuf = await xwb.xlsx.writeBuffer();
    archive.append(Buffer.from(xbuf), { name: xlsxName });
  }

  const indexBuffer = await indexWb.xlsx.writeBuffer();
  archive.append(Buffer.from(indexBuffer), { name: 'master_index.xlsx' });

  archive.finalize();
  await new Promise((resolve, reject) => {
    archive.on('end', resolve);
    archive.on('error', reject);
  });

  return Buffer.concat(chunks);
}

async function renderApp(req, res, options = {}) {
  const stats = await getDashboardStats();
  const section = String(req.query.section || 'clients').trim();
  const normalizedSection = ['clients', 'users', 'audit', 'documents', 'finance', 'loans', 'advisory'].includes(section) ? section : 'clients';
  const advIndustry = String(req.query.advIndustry || '').trim();
  const bankFilter = String(req.query.bank || '').trim();

  const clients = normalizedSection === 'clients' ? await Client.find({}).sort({ createdAt: -1 }).limit(25).lean() : [];
  const users = normalizedSection === 'users' ? await User.find({}).sort({ createdAt: -1 }).lean() : [];
  const auditLogs = normalizedSection === 'audit' ? await AuditLog.find({}).sort({ createdAt: -1 }).limit(100).lean() : [];
  const documents = normalizedSection === 'documents' ? await Document.find({}).sort({ createdAt: -1 }).limit(25).lean() : [];
  const loanApplications = normalizedSection === 'loans' ? await LoanApplication.find(bankFilter ? { bankName: { $regex: bankFilter, $options: 'i' } } : {}).sort({ createdAt: -1 }).limit(50).lean() : [];
  const advisories = normalizedSection === 'advisory' ? await SMEAdvisory.find(advIndustry ? { industry: { $regex: advIndustry, $options: 'i' } } : {}).sort({ createdAt: -1 }).limit(50).lean() : [];
  const latestLoanApplication = loanApplications[0] || null;
  const latestAdvisory = advisories[0] || null;

  const combinedFeed = await Promise.all([ClientActivity.find({}).sort({ createdAt: -1 }).limit(5).lean(), DocumentHistory.find({}).sort({ createdAt: -1 }).limit(5).lean()]).then(([ca, dh]) => [...ca.map((x) => ({ kind: 'client', at: x.createdAt, text: `${x.action}: ${x.details}` })), ...dh.map((x) => ({ kind: 'document', at: x.createdAt, text: `${x.action}: ${x.details}` }))].sort((a, b) => new Date(b.at) - new Date(a.at)).slice(0, 10));

  return res.render('app', {
    title: 'Financial Suite | Dashboard',
    user: req.session.user,
    stats, clients, users, auditLogs, documents, loanApplications, advisories, latestLoanApplication, latestAdvisory, combinedFeed,
    section: normalizedSection, bankFilter, advIndustry,
    navClientsUrl: `/app?${new URLSearchParams({ section: 'clients' })}`,
    navUsersUrl: `/app?${new URLSearchParams({ section: 'users' })}`,
    navAuditUrl: `/app?${new URLSearchParams({ section: 'audit' })}`,
    navDocumentsUrl: `/app?${new URLSearchParams({ section: 'documents' })}`,
    navFinanceUrl: `/app?${new URLSearchParams({ section: 'finance' })}`,
    navLoansUrl: `/app?${new URLSearchParams({ section: 'loans' })}`,
    navAdvisoryUrl: `/app?${new URLSearchParams({ section: 'advisory' })}`,
    error: options.error || null,
    success: options.success || null,
    mongoStatus: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected',
    serverStatus: 'Running'
  });
}

app.get('/', (req, res) => (req.session.user ? res.redirect('/app') : res.redirect('/login')));
app.get('/login', (req, res) => { if (req.session.user) return res.redirect('/app'); renderLogin(res, { mode: 'login' }); });
app.get('/register', (req, res) => { if (req.session.user) return res.redirect('/app'); renderLogin(res, { mode: 'register' }); });

app.post('/register', async (req, res) => { try { const { name, email, password } = req.body; if (!name || !email || !password) return renderLogin(res, { mode: 'register', error: 'All fields are required.' }); const normalizedEmail = String(email).trim().toLowerCase(); if (await User.findOne({ email: normalizedEmail })) return renderLogin(res, { mode: 'register', error: 'This email is already registered.' }); const hashed = await bcrypt.hash(password, SALT_ROUNDS); const user = await User.create({ name: String(name).trim(), email: normalizedEmail, password: hashed, role: 'user', isActive: true }); req.session.user = { id: user._id.toString(), name: user.name, email: user.email, role: user.role }; await writeAudit(req, 'REGISTER', 'user', user._id, 'User registered'); return res.redirect('/app'); } catch (error) { console.error(error); return renderLogin(res, { mode: 'register', error: 'Registration failed.' }); } });
app.post('/login', async (req, res) => { try { const { email, password } = req.body; if (!email || !password) return renderLogin(res, { mode: 'login', error: 'Email and password are required.' }); const normalizedEmail = String(email).trim().toLowerCase(); const user = await User.findOne({ email: normalizedEmail }); if (!user) return renderLogin(res, { mode: 'login', error: 'Invalid email or password.' }); if (!user.isActive) return renderLogin(res, { mode: 'login', error: 'Your account is inactive.' }); const ok = await bcrypt.compare(password, user.password); if (!ok) return renderLogin(res, { mode: 'login', error: 'Invalid email or password.' }); req.session.user = { id: user._id.toString(), name: user.name, email: user.email, role: user.role }; await writeAudit(req, 'LOGIN', 'user', user._id, 'User logged in'); return res.redirect('/app'); } catch (error) { console.error(error); return renderLogin(res, { mode: 'login', error: 'Login failed.' }); } });

app.get('/app', requireAuth, async (req, res) => renderApp(req, res));

app.post('/advisories', requireAuth, async (req, res) => {
  try {
    const input = { businessName: req.body.businessName, industry: req.body.industry, annualTurnover: n(req.body.annualTurnover), ebitda: n(req.body.ebitda), existingDebt: n(req.body.existingDebt), workingCapitalCycleDays: n(req.body.workingCapitalCycleDays), collateralValue: n(req.body.collateralValue), ownerCreditScore: n(req.body.ownerCreditScore), loanAmountRequired: n(req.body.loanAmountRequired), loanPurpose: req.body.loanPurpose, bankPreference: req.body.bankPreference || 'Any', currentAssets: n(req.body.currentAssets), currentLiabilities: n(req.body.currentLiabilities), notes: req.body.notes, createdBy: req.session.user.email };
    const readinessScore = clamp(Math.round((scoreBorrowerProfile(input) * 0.6) + (clamp((n(input.annualTurnover) / Math.max(n(input.loanAmountRequired), 1)) * 10, 0, 25)) + (clamp((n(input.ebitda) / Math.max(n(input.annualTurnover), 1)) * 100, 0, 20)) + (clamp(20 - (n(input.existingDebt) / Math.max(n(input.annualTurnover), 1)) * 20, 0, 20)) + (clamp(20 - (n(input.workingCapitalCycleDays) / 120) * 20, 0, 20))), 0, 100);
    const bankComparison = bankComparisonFromAdvisory(input, readinessScore);
    const lenderMatrix = lenderMatrixFromAdvisory(input, readinessScore);
    const recs = advisoryRecommendations(input, readinessScore, bankComparison);
    const ai = await openaiRecommendations({ advisoryInput: input, readinessScore, bankComparison, lenderMatrix, ...recs });
    const advisory = await SMEAdvisory.create({ ...input, readiness: { score: readinessScore, band: readinessBand(readinessScore), recommendationStatus: readinessScore >= 80 ? 'Proceed' : readinessScore >= 60 ? 'Review' : 'High Risk' }, lenderMatrix, bankComparison, recommendations: { executiveSummary: ai.executiveSummary, strengths: ai.strengths, weaknesses: ai.weaknesses, risks: ai.risks, actions: ai.actions } });
    await writeAudit(req, 'CREATE', 'sme_advisory', advisory._id, 'SME advisory created');
    return res.redirect('/app?section=advisory');
  } catch (error) { console.error(error); return renderApp(req, res, { error: 'Unable to create SME advisory.' }); }
});

app.get('/advisory/:id/pdf', requireAuth, async (req, res) => {
  try {
    const item = await SMEAdvisory.findById(req.params.id).lean();
    if (!item) return res.status(404).send('Advisory not found');
    const browser = await puppeteer.launch({ headless: 'new', args: ['--no-sandbox', '--disable-setuid-sandbox'] });
    const page = await browser.newPage();
    await page.setContent(smeAdvisoryToPdfHtml(item), { waitUntil: 'networkidle0' });
    const pdfBuffer = await page.pdf({ format: 'A4', printBackground: true, preferCSSPageSize: true });
    await browser.close();
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="sme_advisory_${item.businessName.replace(/\s+/g, '_')}.pdf"`);
    return res.send(pdfBuffer);
  } catch (e) { console.error(e); return res.status(500).send('Unable to generate advisory PDF'); }
});

app.get('/advisory/:id/xlsx', requireAuth, async (req, res) => {
  try {
    const item = await SMEAdvisory.findById(req.params.id).lean();
    if (!item) return res.status(404).send('Advisory not found');
    const wb = smeAdvisoryWorkbook(item);
    const buffer = await wb.xlsx.writeBuffer();
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="sme_advisory_${item.businessName.replace(/\s+/g, '_')}.xlsx"`);
    return res.send(Buffer.from(buffer));
  } catch (e) { console.error(e); return res.status(500).send('Unable to generate advisory XLSX'); }
});

app.get('/advisories/:id/report', requireAuth, async (req, res) => {
  try {
    const item = await SMEAdvisory.findById(req.params.id).lean();
    if (!item) return res.status(404).send('Advisory not found');
    return res.json({ success: true, advisory: item });
  } catch (error) { console.error(error); return res.status(500).json({ success: false, message: 'Unable to load advisory report' }); }
});

app.get('/advisory/export-batch.zip', requireAuth, async (req, res) => {
  try {
    const items = await SMEAdvisory.find({}).sort({ createdAt: -1 }).lean();
    const archive = archiver('zip', { zlib: { level: 9 } });
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', 'attachment; filename="advisory_batch_pack.zip"');
    archive.pipe(res);

    const summaryHtml = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Batch Summary</title><style>@page{size:A4;margin:18mm}body{font-family:Arial;margin:24px}h1{color:#0f172a}table{width:100%;border-collapse:collapse}th,td{border:1px solid #e5e7eb;padding:8px;font-size:12px}th{background:#eff6ff}</style></head><body><h1>SME Advisory Batch Summary</h1><p>Total Advisories: ${items.length}</p><table><thead><tr><th>Business</th><th>Industry</th><th>Score</th><th>Band</th><th>Status</th></tr></thead><tbody>${items.map((i) => `<tr><td>${i.businessName}</td><td>${i.industry}</td><td>${i.readiness?.score || 0}</td><td>${i.readiness?.band || ''}</td><td>${i.readiness?.recommendationStatus || ''}</td></tr>`).join('')}</tbody></table></body></html>`;

    const coverBrowser = await puppeteer.launch({ headless: 'new', args: ['--no-sandbox', '--disable-setuid-sandbox'] });
    const coverPage = await coverBrowser.newPage();
    await coverPage.setContent(summaryHtml, { waitUntil: 'networkidle0' });
    const summaryPdf = await coverPage.pdf({ format: 'A4', printBackground: true, preferCSSPageSize: true });
    await coverBrowser.close();
    archive.append(summaryPdf, { name: 'Summary_Cover.pdf' });

    const indexWb = new ExcelJS.Workbook();
    const ws = indexWb.addWorksheet('Index');
    ws.columns = [{ header: 'Business', key: 'business', width: 24 }, { header: 'Industry', key: 'industry', width: 18 }, { header: 'File PDF', key: 'pdf', width: 28 }, { header: 'File XLSX', key: 'xlsx', width: 28 }];

    for (const item of items) {
      const pdfName = `${item.businessName.replace(/\s+/g, '_')}.pdf`;
      const xlsxName = `${item.businessName.replace(/\s+/g, '_')}.xlsx`;
      ws.addRow({ business: item.businessName, industry: item.industry, pdf: pdfName, xlsx: xlsxName });

      const pdfBrowser = await puppeteer.launch({ headless: 'new', args: ['--no-sandbox', '--disable-setuid-sandbox'] });
      const pdfPage = await pdfBrowser.newPage();
      await pdfPage.setContent(smeAdvisoryToPdfHtml(item), { waitUntil: 'networkidle0' });
      const pdfBuffer = await pdfPage.pdf({ format: 'A4', printBackground: true, preferCSSPageSize: true });
      await pdfBrowser.close();
      archive.append(pdfBuffer, { name: pdfName });

      const xwb = smeAdvisoryWorkbook(item);
      const xbuf = await xwb.xlsx.writeBuffer();
      archive.append(Buffer.from(xbuf), { name: xlsxName });
    }

    const indexBuffer = await indexWb.xlsx.writeBuffer();
    archive.append(Buffer.from(indexBuffer), { name: 'master_index.xlsx' });

    await archive.finalize();
  } catch (error) {
    console.error(error);
    return res.status(500).send('Unable to create batch ZIP');
  }
});

app.get('/loan-applications/export-all.xlsx', requireAuth, async (req, res) => {
  try {
    const loans = await LoanApplication.find({}).sort({ createdAt: -1 }).lean();
    const wb = new ExcelJS.Workbook();
    const ws = wb.addWorksheet('All Loan Applications');
    ws.columns = [
      { header: 'Applicant', key: 'applicantName', width: 22 },
      { header: 'Bank', key: 'bankName', width: 14 },
      { header: 'Amount', key: 'amount', width: 14 },
      { header: 'Score', key: 'score', width: 10 },
      { header: 'Risk Band', key: 'risk', width: 12 },
      { header: 'Bank Rating', key: 'rating', width: 12 },
      { header: 'Approval', key: 'approval', width: 12 }
    ];
    loans.forEach((loan) => {
      const rep = createLoanApplicationReportPayload(loan);
      ws.addRow({
        applicantName: loan.applicantName,
        bankName: loan.bankName,
        amount: loan.loanAmountRequested,
        score: rep.scoring.borrowerProfileScore,
        risk: rep.scoring.riskBand,
        rating: rep.scoring.bankWiseRating,
        approval: rep.scoring.approvalStatus
      });
    });
    const buffer = await wb.xlsx.writeBuffer();
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', 'attachment; filename="all_loan_applications.xlsx"');
    return res.send(Buffer.from(buffer));
  } catch (error) {
    console.error(error);
    return res.status(500).send('Unable to export all loans');
  }
});

app.post('/logout', (req, res) => { req.session.destroy(() => { res.clearCookie('connect.sid'); res.redirect('/login'); }); });
app.get('/health', (req, res) => res.json({ status: 'ok', server: 'running', mongo: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected', openai: openai ? 'configured' : 'not-configured' }));
app.use((err, req, res, next) => { console.error(err.message); if (err.message === 'File too large.' || err.message === 'File type not allowed.') return renderApp(req, res, { error: err.message }); return res.status(500).send('Internal server error'); });
app.use((req, res) => { if (req.session.user) return res.status(404).send('Page not found'); return res.redirect('/login'); });

async function startServer() { try { await mongoose.connect(MONGODB_URI, { dbName: 'financial_suite' }); await seedDefaultAdmin(); app.listen(PORT, () => console.log(`Server running on port ${PORT}`)); } catch (error) { console.error('Startup error:', error); process.exit(1); } }
startServer();
