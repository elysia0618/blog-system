// 个人博客系统 - 后端服务
// 技术栈：Node.js + Express + SQLite + JWT
const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = "blog-secret-key-2026";

app.use(express.json({ limit: "2mb" }));
app.use(express.static(path.join(__dirname, "public")));

// ---------- 数据库初始化 ----------
const db = new Database(path.join(__dirname, "blog.db"));
db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  avatar TEXT DEFAULT '',
  created_at TEXT DEFAULT (datetime('now','localtime'))
);
CREATE TABLE IF NOT EXISTS categories (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE NOT NULL
);
CREATE TABLE IF NOT EXISTS posts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  cover TEXT DEFAULT '',
  category TEXT DEFAULT '',
  tags TEXT DEFAULT '[]',
  author_id INTEGER NOT NULL,
  views INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now','localtime')),
  updated_at TEXT DEFAULT (datetime('now','localtime')),
  FOREIGN KEY (author_id) REFERENCES users(id)
);
`);

// 插入默认分类
const catCount = db.prepare("SELECT COUNT(*) as c FROM categories").get().c;
if (catCount === 0) {
  const insert = db.prepare("INSERT INTO categories(name) VALUES(?)");
  ["技术笔记", "生活随笔", "课程作业", "读书感悟"].forEach(n => insert.run(n));
}

// ---------- 鉴权中间件 ----------
function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "未登录" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "登录已过期" });
  }
}

// ---------- 用户接口 ----------
app.post("/api/auth/register", (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: "参数不完整" });
  if (username.length < 2 || username.length > 20) return res.status(400).json({ error: "用户名 2-20 字符" });
  if (password.length < 6) return res.status(400).json({ error: "密码至少 6 位" });
  const exists = db.prepare("SELECT id FROM users WHERE username=? OR email=?").get(username, email);
  if (exists) return res.status(400).json({ error: "用户名或邮箱已存在" });
  const hash = bcrypt.hashSync(password, 10);
  const info = db.prepare("INSERT INTO users(username,email,password) VALUES(?,?,?)").run(username, email, hash);
  res.json({ id: info.lastInsertRowid, username, email });
});

app.post("/api/auth/login", (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare("SELECT * FROM users WHERE username=?").get(username);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(400).json({ error: "用户名或密码错误" });
  }
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ token, user: { id: user.id, username: user.username, email: user.email } });
});

// ---------- 分类接口 ----------
app.get("/api/categories", (req, res) => {
  res.json(db.prepare("SELECT * FROM categories ORDER BY id").all());
});

// ---------- 文章接口 ----------
app.get("/api/posts", (req, res) => {
  const { page = 1, pageSize = 10, category, keyword } = req.query;
  let sql = "SELECT p.*, u.username as author_name FROM posts p JOIN users u ON p.author_id=u.id WHERE 1=1";
  const params = [];
  if (category) { sql += " AND p.category=?"; params.push(category); }
  if (keyword) { sql += " AND (p.title LIKE ? OR p.content LIKE ?)"; params.push(`%${keyword}%`, `%${keyword}%`); }
  sql += " ORDER BY p.created_at DESC LIMIT ? OFFSET ?";
  params.push(Number(pageSize), (Number(page) - 1) * Number(pageSize));
  const list = db.prepare(sql).all(...params);
  let countSql = "SELECT COUNT(*) as total FROM posts p WHERE 1=1";
  const countParams = [];
  if (category) { countSql += " AND p.category=?"; countParams.push(category); }
  if (keyword) { countSql += " AND (p.title LIKE ? OR p.content LIKE ?)"; countParams.push(`%${keyword}%`, `%${keyword}%`); }
  const { total } = db.prepare(countSql).get(...countParams);
  res.json({ list, total, page: Number(page), pageSize: Number(pageSize) });
});

app.get("/api/posts/:id", (req, res) => {
  const post = db.prepare("SELECT p.*, u.username as author_name FROM posts p JOIN users u ON p.author_id=u.id WHERE p.id=?").get(req.params.id);
  if (!post) return res.status(404).json({ error: "文章不存在" });
  db.prepare("UPDATE posts SET views=views+1 WHERE id=?").run(req.params.id);
  post.views += 1;
  res.json(post);
});

app.post("/api/posts", auth, (req, res) => {
  const { title, content, category, tags, cover } = req.body;
  if (!title || !content) return res.status(400).json({ error: "标题和内容不能为空" });
  const info = db.prepare(
    "INSERT INTO posts(title,content,category,tags,cover,author_id) VALUES(?,?,?,?,?,?)"
  ).run(title, content, category || "", JSON.stringify(tags || []), cover || "", req.user.id);
  res.json({ id: info.lastInsertRowid });
});

app.put("/api/posts/:id", auth, (req, res) => {
  const post = db.prepare("SELECT * FROM posts WHERE id=?").get(req.params.id);
  if (!post) return res.status(404).json({ error: "文章不存在" });
  if (post.author_id !== req.user.id) return res.status(403).json({ error: "只能编辑自己的文章" });
  const { title, content, category, tags, cover } = req.body;
  db.prepare(
    "UPDATE posts SET title=?,content=?,category=?,tags=?,cover=?,updated_at=datetime('now','localtime') WHERE id=?"
  ).run(title, content, category || "", JSON.stringify(tags || []), cover || "", req.params.id);
  res.json({ ok: true });
});

app.delete("/api/posts/:id", auth, (req, res) => {
  const post = db.prepare("SELECT * FROM posts WHERE id=?").get(req.params.id);
  if (!post) return res.status(404).json({ error: "文章不存在" });
  if (post.author_id !== req.user.id) return res.status(403).json({ error: "只能删除自己的文章" });
  db.prepare("DELETE FROM posts WHERE id=?").run(req.params.id);
  res.json({ ok: true });
});

// ---------- 启动 ----------
app.listen(PORT, () => {
  console.log(`博客系统运行在 http://localhost:${PORT}`);
});
