import "dotenv/config";
import express from "express";
import pg from "pg";
import bcrypt from "bcryptjs";
import cookieParser from "cookie-parser";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import nodemailer from "nodemailer";
import { randomBytes, createHash } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

if (!process.env.DATABASE_URL) throw Error("Configure DATABASE_URL");
const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
const app = express();
app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "32kb" }));
app.use(cookieParser());
const origin = process.env.APP_ORIGIN || "http://localhost:3000";
app.use("/api", (req, res, next) => {
  if (
    !["GET", "HEAD", "OPTIONS"].includes(req.method) &&
    req.get("origin") !== origin
  )
    return res.status(403).json({ error: "Origem não autorizada" });
  next();
});
const authLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 15,
  standardHeaders: "draft-7",
  legacyHeaders: false,
});
const sha = (s) => createHash("sha256").update(s).digest("hex");
const token = () => randomBytes(32).toString("hex");
const cookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "strict",
  path: "/",
};
const asyncRoute = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);
const err = (res, msg, status = 400) => res.status(status).json({ error: msg });
async function auth(req, res, next) {
  try {
    const raw = req.cookies.bc_session;
    if (!raw) return err(res, "Sessão necessária", 401);
    const { rows } = await pool.query(
      `SELECT u.id,u.username,u.name,u.email,u.role,u.can_create,u.can_edit,u.can_delete FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>now() AND u.active=true`,
      [sha(raw)],
    );
    if (!rows[0]) return err(res, "Sessão inválida", 401);
    req.user = rows[0];
    next();
  } catch (e) {
    next(e);
  }
}
const admin = (req, res, next) =>
  req.user.role === "admin"
    ? next()
    : err(res, "Acesso reservado ao administrador", 403);
const isAdmin = (u) => u.role === "admin";
async function projectAccess(u, id) {
  if (isAdmin(u))
    return (
      (await pool.query("SELECT 1 FROM projects WHERE id=$1", [id])).rowCount >
      0
    );
  return (
    (
      await pool.query(
        "SELECT 1 FROM project_members WHERE project_id=$1 AND user_id=$2",
        [id, u.id],
      )
    ).rowCount > 0
  );
}
function validExpense(b) {
  return (
    typeof b.title === "string" &&
    b.title.trim().length > 0 &&
    b.title.length <= 120 &&
    ["Hardware", "Serviços", "Software", "Outros"].includes(b.category) &&
    Number.isFinite(Number(b.amount)) &&
    Number(b.amount) > 0 &&
    Number(b.amount) <= 999999999999 &&
    typeof b.method === "string" &&
    b.method.trim().length > 0 &&
    b.method.length <= 80 &&
    /^\d{4}-\d{2}-\d{2}$/.test(b.date) &&
    !Number.isNaN(Date.parse(b.date))
  );
}
const userFields =
  "id,username,name,email,role,can_create,can_edit,can_delete,active";
app.post(
  "/api/auth/register",
  authLimit,
  asyncRoute(async (req, res) => {
    const { username, name, email, password } = req.body;
    if (
      typeof username !== "string" ||
      !/^[a-zA-Z0-9_.-]{3,40}$/.test(username) ||
      typeof name !== "string" ||
      !name.trim() ||
      name.length > 100 ||
      typeof email !== "string" ||
      email.length > 200 ||
      !/^\S+@\S+\.\S+$/.test(email) ||
      typeof password !== "string" ||
      password.length < 10 ||
      password.length > 128
    )
      return err(res, "Dados inválidos (palavra-passe: mínimo 10 caracteres)");
    try {
      await pool.query(
        "INSERT INTO users(username,name,email,password_hash) VALUES($1,$2,$3,$4)",
        [
          username.trim(),
          name.trim(),
          email.trim().toLowerCase(),
          await bcrypt.hash(password, 12),
        ],
      );
      res
        .status(201)
        .json({ message: "Conta criada. Aguarde a atribuição de projetos." });
    } catch (e) {
      if (e.code === "23505")
        return err(res, "Utilizador ou email já existente", 409);
      throw e;
    }
  }),
);
app.post(
  "/api/auth/login",
  authLimit,
  asyncRoute(async (req, res) => {
    const { login, password } = req.body;
    if (typeof login !== "string" || typeof password !== "string")
      return err(res, "Credenciais inválidas", 401);
    const { rows } = await pool.query(
      "SELECT * FROM users WHERE (lower(username)=lower($1) OR lower(email)=lower($1)) AND active=true",
      [login],
    );
    if (!rows[0] || !(await bcrypt.compare(password, rows[0].password_hash)))
      return err(res, "Credenciais inválidas", 401);
    const raw = token();
    await pool.query(
      "INSERT INTO sessions(token_hash,user_id,expires_at) VALUES($1,$2,now()+interval '7 days')",
      [sha(raw), rows[0].id],
    );
    res.cookie("bc_session", raw, { ...cookieOptions, maxAge: 7 * 86400000 });
    res.json({ message: "Sessão iniciada" });
  }),
);
app.post(
  "/api/auth/logout",
  auth,
  asyncRoute(async (req, res) => {
    await pool.query("DELETE FROM sessions WHERE token_hash=$1", [
      sha(req.cookies.bc_session),
    ]);
    res.clearCookie("bc_session", cookieOptions);
    res.json({ ok: true });
  }),
);
app.get("/api/me", auth, (req, res) => res.json(req.user));
async function sendMail(to, subject, text) {
  if (!process.env.SMTP_HOST) throw Error("SMTP não configurado");
  const transport = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: Number(process.env.SMTP_PORT) === 465,
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  });
  await transport.sendMail({ from: process.env.SMTP_FROM, to, subject, text });
}
app.post(
  "/api/auth/recover-username",
  authLimit,
  asyncRoute(async (req, res) => {
    const email = String(req.body.email || "")
      .trim()
      .toLowerCase();
    if (!process.env.SMTP_HOST)
      return err(res, "Recuperação por email ainda não configurada", 503);
    const { rows } = await pool.query(
      "SELECT username,email FROM users WHERE lower(email)=$1 AND active=true",
      [email],
    );
    if (rows[0])
      await sendMail(
        rows[0].email,
        "Budget Control — Utilizador",
        `O seu nome de utilizador é: ${rows[0].username}`,
      );
    res.json({ message: "Se a conta existir, receberá um email." });
  }),
);
app.post(
  "/api/auth/forgot-password",
  authLimit,
  asyncRoute(async (req, res) => {
    const email = String(req.body.email || "")
      .trim()
      .toLowerCase();
    if (!process.env.SMTP_HOST)
      return err(res, "Recuperação por email ainda não configurada", 503);
    const { rows } = await pool.query(
      "SELECT id,email FROM users WHERE lower(email)=$1 AND active=true",
      [email],
    );
    if (rows[0]) {
      const raw = token();
      await pool.query(
        "INSERT INTO reset_tokens(token_hash,user_id,expires_at) VALUES($1,$2,now()+interval '30 minutes')",
        [sha(raw), rows[0].id],
      );
      await sendMail(
        rows[0].email,
        "Budget Control — Recuperar palavra-passe",
        `Aceda a ${origin}/?reset=${raw} (válido durante 30 minutos).`,
      );
    }
    res.json({ message: "Se a conta existir, receberá um email." });
  }),
);
app.post(
  "/api/auth/reset-password",
  authLimit,
  asyncRoute(async (req, res) => {
    const { token: raw, password } = req.body;
    if (
      typeof raw !== "string" ||
      typeof password !== "string" ||
      password.length < 10 ||
      password.length > 128
    )
      return err(res, "Pedido inválido");
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const { rows } = await client.query(
        "DELETE FROM reset_tokens WHERE token_hash=$1 AND expires_at>now() RETURNING user_id",
        [sha(raw)],
      );
      if (!rows[0]) {
        await client.query("ROLLBACK");
        return err(res, "Ligação inválida ou expirada", 400);
      }
      await client.query("UPDATE users SET password_hash=$1 WHERE id=$2", [
        await bcrypt.hash(password, 12),
        rows[0].user_id,
      ]);
      await client.query("DELETE FROM sessions WHERE user_id=$1", [
        rows[0].user_id,
      ]);
      await client.query("COMMIT");
      res.json({ message: "Palavra-passe atualizada" });
    } catch (e) {
      await client.query("ROLLBACK");
      throw e;
    } finally {
      client.release();
    }
  }),
);
app.get(
  "/api/projects",
  auth,
  asyncRoute(async (req, res) => {
    const { rows } = await pool.query(
      `SELECT p.id,p.name,p.budget::float8 AS budget,COALESCE(sum(e.amount),0)::float8 AS spent FROM projects p LEFT JOIN expenses e ON e.project_id=p.id WHERE ($1::boolean OR EXISTS(SELECT 1 FROM project_members m WHERE m.project_id=p.id AND m.user_id=$2)) GROUP BY p.id ORDER BY p.name`,
      [isAdmin(req.user), req.user.id],
    );
    res.json(rows);
  }),
);
app.get(
  "/api/projects/:id/expenses",
  auth,
  asyncRoute(async (req, res) => {
    if (!(await projectAccess(req.user, req.params.id)))
      return err(res, "Projeto não autorizado", 403);
    const { rows } = await pool.query(
      `SELECT e.id,e.project_id,e.owner_id,e.title,e.category,e.amount::float8 AS amount,e.method,to_char(e.expense_date,'YYYY-MM-DD') AS date,u.name AS owner_name FROM expenses e JOIN users u ON u.id=e.owner_id WHERE e.project_id=$1 AND ($2::boolean OR e.owner_id=$3) ORDER BY e.expense_date DESC,e.created_at DESC`,
      [req.params.id, isAdmin(req.user), req.user.id],
    );
    res.json(rows);
  }),
);
app.get(
  "/api/projects/:id/summary",
  auth,
  asyncRoute(async (req, res) => {
    if (!(await projectAccess(req.user, req.params.id)))
      return err(res, "Projeto não autorizado", 403);
    const { rows } = await pool.query(
      "SELECT category,sum(amount)::float8 AS total FROM expenses WHERE project_id=$1 GROUP BY category",
      [req.params.id],
    );
    res.json(rows);
  }),
);
app.post(
  "/api/expenses",
  auth,
  asyncRoute(async (req, res) => {
    const b = req.body;
    if (!isAdmin(req.user) && !req.user.can_create)
      return err(res, "Criação bloqueada", 403);
    if (
      typeof b.project_id !== "string" ||
      !(await projectAccess(req.user, b.project_id))
    )
      return err(res, "Projeto não autorizado", 403);
    if (!validExpense(b)) return err(res, "Dados da despesa inválidos");
    const { rows } = await pool.query(
      "INSERT INTO expenses(project_id,owner_id,title,category,amount,method,expense_date) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id",
      [
        b.project_id,
        req.user.id,
        b.title.trim(),
        b.category,
        b.amount,
        b.method.trim(),
        b.date,
      ],
    );
    res.status(201).json(rows[0]);
  }),
);
app.patch(
  "/api/expenses/:id",
  auth,
  asyncRoute(async (req, res) => {
    if (!isAdmin(req.user) && !req.user.can_edit)
      return err(res, "Edição bloqueada", 403);
    if (!validExpense(req.body)) return err(res, "Dados inválidos");
    const { rows } = await pool.query(
      `UPDATE expenses SET title=$1,category=$2,amount=$3,method=$4,expense_date=$5 WHERE id=$6 AND ($7::boolean OR (owner_id=$8 AND EXISTS(SELECT 1 FROM project_members WHERE project_id=expenses.project_id AND user_id=$8))) RETURNING id`,
      [
        req.body.title.trim(),
        req.body.category,
        req.body.amount,
        req.body.method.trim(),
        req.body.date,
        req.params.id,
        isAdmin(req.user),
        req.user.id,
      ],
    );
    if (!rows[0])
      return err(res, "Despesa não encontrada ou sem autorização", 404);
    res.json(rows[0]);
  }),
);
app.delete(
  "/api/expenses/:id",
  auth,
  asyncRoute(async (req, res) => {
    if (!isAdmin(req.user) && !req.user.can_delete)
      return err(res, "Eliminação bloqueada", 403);
    const { rowCount } = await pool.query(
      `DELETE FROM expenses WHERE id=$1 AND ($2::boolean OR (owner_id=$3 AND EXISTS(SELECT 1 FROM project_members WHERE project_id=expenses.project_id AND user_id=$3)))`,
      [req.params.id, isAdmin(req.user), req.user.id],
    );
    if (!rowCount)
      return err(res, "Despesa não encontrada ou sem autorização", 404);
    res.json({ ok: true });
  }),
);
app.get(
  "/api/admin/users",
  auth,
  admin,
  asyncRoute(async (req, res) =>
    res.json(
      (await pool.query(`SELECT ${userFields} FROM users ORDER BY name`)).rows,
    ),
  ),
);
app.patch(
  "/api/admin/users/:id",
  auth,
  admin,
  asyncRoute(async (req, res) => {
    const b = req.body;
    if (
      typeof b.can_create !== "boolean" ||
      typeof b.can_edit !== "boolean" ||
      typeof b.can_delete !== "boolean"
    )
      return err(res, "Permissões inválidas");
    const { rows } = await pool.query(
      `UPDATE users SET can_create=$1,can_edit=$2,can_delete=$3 WHERE id=$4 AND role='user' RETURNING ${userFields}`,
      [b.can_create, b.can_edit, b.can_delete, req.params.id],
    );
    if (!rows[0]) return err(res, "Utilizador não encontrado", 404);
    res.json(rows[0]);
  }),
);
app.get(
  "/api/admin/projects/:id/members",
  auth,
  admin,
  asyncRoute(async (req, res) =>
    res.json(
      (
        await pool.query(
          "SELECT user_id FROM project_members WHERE project_id=$1",
          [req.params.id],
        )
      ).rows.map((x) => x.user_id),
    ),
  ),
);
app.put(
  "/api/admin/projects/:id/members/:userId",
  auth,
  admin,
  asyncRoute(async (req, res) => {
    const exists = await pool.query(
      "SELECT 1 FROM users WHERE id=$1 AND role='user'",
      [req.params.userId],
    );
    if (!exists.rowCount) return err(res, "Utilizador inválido", 404);
    const project = await pool.query("SELECT 1 FROM projects WHERE id=$1", [
      req.params.id,
    ]);
    if (!project.rowCount) return err(res, "Projeto inválido", 404);
    await pool.query(
      "INSERT INTO project_members(project_id,user_id) VALUES($1,$2) ON CONFLICT DO NOTHING",
      [req.params.id, req.params.userId],
    );
    res.json({ ok: true });
  }),
);
app.delete(
  "/api/admin/projects/:id/members/:userId",
  auth,
  admin,
  asyncRoute(async (req, res) => {
    await pool.query(
      "DELETE FROM project_members WHERE project_id=$1 AND user_id=$2",
      [req.params.id, req.params.userId],
    );
    res.json({ ok: true });
  }),
);
app.post(
  "/api/admin/projects",
  auth,
  admin,
  asyncRoute(async (req, res) => {
    const { name, budget } = req.body;
    if (
      typeof name !== "string" ||
      !name.trim() ||
      name.length > 120 ||
      !Number.isFinite(Number(budget)) ||
      Number(budget) < 0
    )
      return err(res, "Projeto inválido");
    res
      .status(201)
      .json(
        (
          await pool.query(
            "INSERT INTO projects(name,budget) VALUES($1,$2) RETURNING id",
            [name.trim(), budget],
          )
        ).rows[0],
      );
  }),
);
app.patch(
  "/api/admin/projects/:id",
  auth,
  admin,
  asyncRoute(async (req, res) => {
    if (
      !Number.isFinite(Number(req.body.budget)) ||
      Number(req.body.budget) < 0
    )
      return err(res, "Orçamento inválido");
    const { rows } = await pool.query(
      "UPDATE projects SET budget=$1 WHERE id=$2 RETURNING id",
      [req.body.budget, req.params.id],
    );
    if (!rows[0]) return err(res, "Projeto inexistente", 404);
    res.json(rows[0]);
  }),
);
app.get(
  "/api/admin/expenses",
  auth,
  admin,
  asyncRoute(async (req, res) => {
    const { user_id = "", project_id = "" } = req.query;
    const { rows } = await pool.query(
      `SELECT e.id,e.project_id,e.owner_id,e.title,e.category,e.amount::float8 AS amount,e.method,to_char(e.expense_date,'YYYY-MM-DD') AS date,u.name AS owner_name,p.name AS project_name FROM expenses e JOIN users u ON u.id=e.owner_id JOIN projects p ON p.id=e.project_id WHERE ($1::text='' OR e.owner_id::text=$1) AND ($2::text='' OR e.project_id::text=$2) ORDER BY e.expense_date DESC LIMIT 2000`,
      [user_id, project_id],
    );
    res.json(rows);
  }),
);
app.use(
  express.static(
    path.join(path.dirname(fileURLToPath(import.meta.url)), "public"),
  ),
);
app.use((e, req, res, next) => {
  console.error(e);
  res.status(500).json({ error: "Erro interno do servidor" });
});
const port = Number(process.env.PORT || 3000);
app.listen(port, () => console.log(`Budget Control: ${origin}`));
