import "dotenv/config";
import express from "express";
import session from "express-session";
import MySQLStoreFactory from "express-mysql-session";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import bcrypt from "bcryptjs";
import multer from "multer";
import mysql from "mysql2/promise";
import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const port = Number(process.env.PORT || 3000);
const isProduction = process.env.NODE_ENV === "production";
const sessionSecret = String(process.env.SESSION_SECRET || "");
if (isProduction && sessionSecret.length < 32) {
  throw new Error("SESSION_SECRET must be at least 32 characters in production.");
}
app.set("trust proxy", 1);
app.disable("x-powered-by");
const uploadDir = path.join(__dirname, "uploads");
await fs.mkdir(uploadDir, { recursive: true });

const pool = mysql.createPool({
  host: process.env.MYSQL_HOST || "127.0.0.1",
  port: Number(process.env.MYSQL_PORT || 3306),
  user: process.env.MYSQL_USER || "root",
  password: process.env.MYSQL_PASSWORD || "",
  database: process.env.MYSQL_DATABASE || "al_huda_accreditation",
  waitForConnections: true,
  connectionLimit: 10,
  charset: "utf8mb4"
});

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "20mb" }));
app.use(express.urlencoded({ extended: true, limit: "2mb", parameterLimit: 100 }));
const MySQLStore = MySQLStoreFactory(session);
const sessionStore = new MySQLStore({}, pool);
app.use(session({
  name: "alhuda.sid",
  store: sessionStore,
  secret: sessionSecret || "development-only-session-secret-change-me",
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "strict", secure: isProduction, maxAge: 1000 * 60 * 60 * 8 }
}));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { ok: false, message: "تم تجاوز عدد محاولات الدخول. حاول لاحقًا." }
});

const storage = multer.diskStorage({
  destination: uploadDir,
  filename: (_req, file, callback) => callback(null, `${Date.now()}-${crypto.randomBytes(8).toString("hex")}${path.extname(file.originalname).toLowerCase()}`)
});
const upload = multer({
  storage,
  limits: { fileSize: 25 * 1024 * 1024 },
  fileFilter: (_req, file, callback) => callback(null, /^(application|image|text|audio|video)\//.test(file.mimetype) || file.mimetype === "application/pdf")
});

const json = (value) => JSON.stringify(value ?? {}, null, 0);
const send = (res, body, status = 200) => res.status(status).json(body);
const adminOnly = (req, res, next) => req.session.admin ? next() : send(res, { ok: false, message: "يجب تسجيل الدخول كأدمن." }, 401);

async function ensureAdmin() {
  const [columns] = await pool.query("SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'admins'");
  const names = new Set(columns.map(column => column.COLUMN_NAME));
  if (names.has("username") && !names.has("email")) {
    await pool.query("ALTER TABLE admins CHANGE COLUMN username email VARCHAR(190) NOT NULL");
  }
  const [rows] = await pool.query("SELECT id FROM admins LIMIT 1");
  if (!rows.length) {
    const email = String(process.env.ADMIN_EMAIL || "").trim().toLowerCase();
    const password = String(process.env.ADMIN_PASSWORD || "");
    if (!email || password.length < 8) {
      throw new Error("No admin account exists. Set ADMIN_EMAIL and ADMIN_PASSWORD before starting the server.");
    }
    await pool.execute("INSERT INTO admins (email, password_hash) VALUES (?, ?)", [email, await bcrypt.hash(password, 12)]);
  }
}

async function readState() {
  const [rows] = await pool.query("SELECT state_key, state_json FROM platform_state");
  return Object.fromEntries(rows.map(row => [row.state_key, JSON.parse(row.state_json)]));
}

async function saveState(state) {
  for (const key of ["assessments", "content", "compliance", "improvement"]) {
    if (!(key in state)) continue;
    await pool.execute(
      "INSERT INTO platform_state (state_key, state_json) VALUES (?, ?) ON DUPLICATE KEY UPDATE state_json = VALUES(state_json)",
      [key, json(state[key])]
    );
  }
}

app.get("/api/state", async (req, res) => {
  try {
    const authenticated = Boolean(req.session.admin);
    return send(res, { ok: true, authenticated, state: authenticated ? await readState() : {} });
  }
  catch (error) { console.error(error); return send(res, { ok: false, message: "تعذر قراءة قاعدة البيانات." }, 500); }
});

app.post("/api/login", loginLimiter, async (req, res) => {
  try {
    const [rows] = await pool.execute("SELECT id, email, password_hash FROM admins WHERE email = ? LIMIT 1", [String(req.body.email || "").trim().toLowerCase()]);
    const admin = rows[0];
    if (!admin || !(await bcrypt.compare(String(req.body.password || ""), admin.password_hash))) return send(res, { ok: false, message: "البريد الإلكتروني أو كلمة المرور غير صحيحة." }, 401);
    req.session.admin = { id: admin.id, email: admin.email };
    return send(res, { ok: true, authenticated: true });
  } catch (error) { console.error(error); return send(res, { ok: false, message: "تعذر تسجيل الدخول." }, 500); }
});

app.post("/api/logout", (req, res) => req.session.destroy(() => send(res, { ok: true })));

app.post("/api/state", adminOnly, async (req, res) => {
  try { await saveState(req.body || {}); return send(res, { ok: true }); }
  catch (error) { console.error(error); return send(res, { ok: false, message: "تعذر حفظ البيانات في MySQL." }, 500); }
});

app.post("/api/credentials", adminOnly, async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  if (!email || !password || !/^\S+@\S+\.\S+$/.test(email)) return send(res, { ok: false, message: "أدخل بريدًا إلكترونيًا وكلمة مرور صحيحة." }, 422);
  try {
    await pool.execute("UPDATE admins SET email = ?, password_hash = ? WHERE id = ?", [email, await bcrypt.hash(password, 12), req.session.admin.id]);
    req.session.admin.email = email;
    return send(res, { ok: true });
  } catch (error) { console.error(error); return send(res, { ok: false, message: "تعذر تحديث بيانات الدخول." }, 500); }
});

app.post("/api/admins", adminOnly, async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  if (!email || !/^\S+@\S+\.\S+$/.test(email) || password.length < 8) {
    return send(res, { ok: false, message: "أدخل بريدًا صحيحًا وكلمة مرور لا تقل عن 8 أحرف." }, 422);
  }
  try {
    await pool.execute("INSERT INTO admins (email, password_hash) VALUES (?, ?)", [email, await bcrypt.hash(password, 12)]);
    return send(res, { ok: true });
  } catch (error) {
    if (error.code === "ER_DUP_ENTRY") return send(res, { ok: false, message: "هذا البريد مسجل مسبقًا." }, 409);
    console.error(error);
    return send(res, { ok: false, message: "تعذر إضافة حساب الأدمن." }, 500);
  }
});

app.post("/api/indicator-file", adminOnly, upload.single("file"), async (req, res) => {
  if (!req.file) return send(res, { ok: false, message: "لم يتم اختيار ملف صالح." }, 422);
  const { criterionNumber, elementIndex, pointIndex } = req.body;
  try {
    const relativePath = `/uploads/${req.file.filename}`;
    const fileData = await fs.readFile(req.file.path);
    await pool.execute(
      `INSERT INTO indicator_files (criterion_number, element_index, point_index, original_name, stored_name, mime_type, file_size, file_data, relative_path, uploaded_by)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE original_name=VALUES(original_name), stored_name=VALUES(stored_name), mime_type=VALUES(mime_type), file_size=VALUES(file_size), file_data=VALUES(file_data), relative_path=VALUES(relative_path), uploaded_by=VALUES(uploaded_by)`,
      [String(criterionNumber), Number(elementIndex), Number(pointIndex), req.file.originalname, req.file.filename, req.file.mimetype, req.file.size, fileData, relativePath, req.session.admin.id]
    );
    const [rows] = await pool.execute("SELECT id FROM indicator_files WHERE criterion_number = ? AND element_index = ? AND point_index = ?", [String(criterionNumber), Number(elementIndex), Number(pointIndex)]);
    await fs.rm(req.file.path, { force: true });
    return send(res, { ok: true, url: `/api/indicator-file/${rows[0].id}`, name: req.file.originalname });
  } catch (error) { await fs.rm(req.file.path, { force: true }); console.error(error); return send(res, { ok: false, message: "تعذر حفظ الملف." }, 500); }
});

app.get("/api/indicator-file/:id", adminOnly, async (req, res) => {
  try {
    const [rows] = await pool.execute("SELECT original_name, mime_type, file_data FROM indicator_files WHERE id = ? LIMIT 1", [Number(req.params.id)]);
    if (!rows.length) return res.status(404).send("File not found");
    res.setHeader("Content-Type", rows[0].mime_type || "application/octet-stream");
    res.setHeader("Content-Disposition", `inline; filename*=UTF-8''${encodeURIComponent(rows[0].original_name)}`);
    return res.send(rows[0].file_data);
  } catch (error) { console.error(error); return res.status(500).send("Unable to read file"); }
});
app.get(["/", "/index.html"], (_req, res) => res.sendFile(path.join(__dirname, "index.html")));

try {
  await ensureAdmin();
  app.listen(port, () => console.log(`Accreditation platform listening on http://localhost:${port}`));
} catch (error) {
  console.error("MySQL connection failed. Check MYSQL_HOST, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DATABASE.", error);
  process.exit(1);
}
