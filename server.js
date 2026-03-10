const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const JWT_SECRET = 'company-tasks-secret-2025';
const DB_FILE = path.join(__dirname, 'db.json');

// قراءة قاعدة البيانات
function readDB() {
  if (!fs.existsSync(DB_FILE)) {
    const init = {
      users: [
        { name: 'slom', password: bcrypt.hashSync('slom190', 10), role: 'manager', email: '' },
        { name: 'اكرم', password: bcrypt.hashSync('akrem121', 10), role: 'employee', email: 'ssloommxxx@gmail.com', phone: '966591252469' }
      ],
      tasks: []
    };
    fs.writeFileSync(DB_FILE, JSON.stringify(init, null, 2));
    return init;
  }
  return JSON.parse(fs.readFileSync(DB_FILE));
}

// حفظ قاعدة البيانات
function writeDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

// تسجيل الدخول
app.post('/api/login', (req, res) => {
  const { password } = req.body;
  const db = readDB();
  const user = db.users.find(u => bcrypt.compareSync(password, u.password));
  if (!user) return res.status(401).json({ error: 'كلمة السر غلط' });
  const token = jwt.sign({ name: user.name, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, name: user.name, role: user.role });
});

// التحقق من التوكن
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'غير مصرح' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch { res.status(401).json({ error: 'توكن منتهي' }); }
}

// جلب المهام
app.get('/api/tasks', auth, (req, res) => {
  const db = readDB();
  const tasks = req.user.role === 'manager'
    ? db.tasks
    : db.tasks.filter(t => t.assignee === req.user.name);
  res.json(tasks);
});

// إضافة مهمة
app.post('/api/tasks', auth, (req, res) => {
  if (req.user.role !== 'manager') return res.status(403).json({ error: 'غير مصرح' });
  const db = readDB();
  const task = { id: Date.now(), ...req.body, done: false };
  db.tasks.unshift(task);
  writeDB(db);
  res.json(task);
});

// تحديث مهمة
app.put('/api/tasks/:id', auth, (req, res) => {
  const db = readDB();
  const idx = db.tasks.findIndex(t => t.id == req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'مو موجودة' });
  db.tasks[idx] = { ...db.tasks[idx], ...req.body };
  writeDB(db);
  res.json(db.tasks[idx]);
});

// حذف مهمة
app.delete('/api/tasks/:id', auth, (req, res) => {
  if (req.user.role !== 'manager') return res.status(403).json({ error: 'غير مصرح' });
  const db = readDB();
  db.tasks = db.tasks.filter(t => t.id != req.params.id);
  writeDB(db);
  res.json({ ok: true });
});

// جلب الموظفين
app.get('/api/users', auth, (req, res) => {
  if (req.user.role !== 'manager') return res.status(403).json({ error: 'غير مصرح' });
  const db = readDB();
  const employees = db.users.filter(u => u.role === 'employee').map(u => ({
    name: u.name, email: u.email, phone: u.phone, role: u.role
  }));
  res.json(employees);
});

// إضافة موظف
app.post('/api/users', auth, (req, res) => {
  if (req.user.role !== 'manager') return res.status(403).json({ error: 'غير مصرح' });
  const db = readDB();
  const { name, password, email, phone } = req.body;
  if (db.users.find(u => u.name === name)) return res.status(400).json({ error: 'الاسم موجود' });
  db.users.push({ name, password: bcrypt.hashSync(password, 10), role: 'employee', email, phone });
  writeDB(db);
  res.json({ ok: true });
});

// حذف موظف
app.delete('/api/users/:name', auth, (req, res) => {
  if (req.user.role !== 'manager') return res.status(403).json({ error: 'غير مصرح' });
  const db = readDB();
  db.users = db.users.filter(u => u.name !== req.params.name);
  writeDB(db);
  res.json({ ok: true });
});

// تحديث موظف
app.put('/api/users/:name', auth, (req, res) => {
  if (req.user.role !== 'manager') return res.status(403).json({ error: 'غير مصرح' });
  const db = readDB();
  const idx = db.users.findIndex(u => u.name === req.params.name);
  if (idx === -1) return res.status(404).json({ error: 'موظف غير موجود' });
  const { email, phone, password } = req.body;
  if (email) db.users[idx].email = email;
  if (phone) db.users[idx].phone = phone;
  if (password) db.users[idx].password = bcrypt.hashSync(password, 10);
  writeDB(db);
  res.json({ ok: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
