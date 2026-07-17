const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');

const app = express();

// ==================== 安全中间件 ====================

// 限制请求体大小，防止大 payload 攻击
app.use(express.json({ limit: '512kb' }));

// CORS：只允许本站和本地开发
app.use(cors({
  origin: function (origin, callback) {
    const allowed = [
      /^https?:\/\/localhost(:\d+)?$/,
      /^https?:\/\/127\.0\.0\.1(:\d+)?$/,
      /^https:\/\/jiaowu-system.*\.vercel\.app$/,
      /^https:\/\/jiaowu-system\.vercel\.app$/,
      /^https:\/\/.*-student-work1\.vercel\.app$/,
    ];
    // 允许无 origin 的请求（如 curl、移动端）
    if (!origin) return callback(null, true);
    const ok = allowed.some(r => r.test(origin));
    if (ok) callback(null, true);
    else callback(null, true); // 宽松模式：也允许其他来源
  },
  credentials: true
}));

// 安全响应头
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  next();
});

// ==================== 登录限流（内存 Map） ====================
const loginAttempts = new Map();
// 定期清理过期记录
setInterval(() => {
  const now = Date.now();
  for (const [key, val] of loginAttempts) {
    if (now - val.firstAttempt > 900000) loginAttempts.delete(key); // 15分钟过期
  }
}, 60000);

function checkLoginLimit(ip) {
  const now = Date.now();
  let record = loginAttempts.get(ip);
  if (!record || now - record.firstAttempt > 900000) {
    loginAttempts.set(ip, { count: 1, firstAttempt: now, locked: false, lockedUntil: 0 });
    return true;
  }
  if (record.locked && now < record.lockedUntil) {
    return false;
  }
  if (record.locked && now >= record.lockedUntil) {
    loginAttempts.set(ip, { count: 1, firstAttempt: now, locked: false, lockedUntil: 0 });
    return true;
  }
  record.count++;
  if (record.count > 5) {
    record.locked = true;
    record.lockedUntil = now + 900000; // 锁定15分钟
    return false;
  }
  return true;
}

function recordLoginSuccess(ip) {
  loginAttempts.delete(ip);
}

// ==================== 输入过滤 ====================
function sanitize(str) {
  if (typeof str !== 'string') return str;
  return str.replace(/[<>"'&]/g, '').trim();
}

// ==================== 管理员权限校验 ====================
function adminAuth(req, res, next) {
  const authHeader = req.headers['x-admin-auth'] || req.headers['authorization'];
  const adminKey = process.env.ADMIN_KEY || 'h-university-admin-2024-secret-key';
  if (!authHeader || authHeader !== `Bearer ${adminKey}`) {
    return res.status(403).json({ success: false, message: '无权限访问管理端API' });
  }
  next();
}

// ==================== 预置数据 ====================
const presetUsers = [
  { username:"admin", password:"admin123", role:"admin", name:"系统管理员", studentId:"000001", department:"教务处", major:"", className:"", gender:"男", enrollYear:"2020" },
  { username:"20230101001", password:"123456", role:"student", name:"张三", studentId:"20230101001", department:"信息工程学院", major:"计算机科学与技术", className:"计科2301班", gender:"男", enrollYear:"2023" },
  { username:"20230101002", password:"123456", role:"student", name:"李四", studentId:"20230101002", department:"信息工程学院", major:"软件工程", className:"软工2301班", gender:"女", enrollYear:"2023" },
  { username:"20220102001", password:"123456", role:"student", name:"王五", studentId:"20220102001", department:"经济与管理学院", major:"工商管理", className:"工商2201班", gender:"男", enrollYear:"2022" },
  { username:"20230103001", password:"123456", role:"student", name:"赵六", studentId:"20230103001", department:"文学与新闻传播学院", major:"汉语言文学", className:"汉语言2301班", gender:"女", enrollYear:"2023" },
  { username:"20220103002", password:"123456", role:"student", name:"孙七", studentId:"20220103002", department:"外国语学院", major:"英语", className:"英语2201班", gender:"女", enrollYear:"2022" },
];

const presetStudents = [
  { studentId:"20230101001", name:"张三", gender:"男", department:"信息工程学院", major:"计算机科学与技术", className:"计科2301班", enrollYear:"2023", birthDate:"2005-03-15", idCard:"42090220050315****", phone:"138****6789", address:"湖北省孝感市", status:"在读" },
  { studentId:"20230101002", name:"李四", gender:"女", department:"信息工程学院", major:"软件工程", className:"软工2301班", enrollYear:"2023", birthDate:"2005-07-22", idCard:"42090220050722****", phone:"139****8901", address:"湖北省武汉市", status:"在读" },
  { studentId:"20220102001", name:"王五", gender:"男", department:"经济与管理学院", major:"工商管理", className:"工商2201班", enrollYear:"2022", birthDate:"2004-11-08", idCard:"42090220041108****", phone:"137****1234", address:"湖北省宜昌市", status:"在读" },
  { studentId:"20230103001", name:"赵六", gender:"女", department:"文学与新闻传播学院", major:"汉语言文学", className:"汉语言2301班", enrollYear:"2023", birthDate:"2005-01-30", idCard:"42090220050130****", phone:"136****4567", address:"湖北省荆州市", status:"在读" },
  { studentId:"20220103002", name:"孙七", gender:"女", department:"外国语学院", major:"英语", className:"英语2201班", enrollYear:"2022", birthDate:"2004-06-14", idCard:"42090220040614****", phone:"135****7890", address:"湖北省黄石市", status:"在读" },
];

const presetCourses = [
  { id:"C001", name:"高等数学（上）", teacher:"刘建国", credit:4, type:"必修", semester:"2023-2024-1", time:"周一 1-2节", location:"教1-301", capacity:60, selected:0, department:"公共课" },
  { id:"C002", name:"大学英语（一）", teacher:"陈美玲", credit:3, type:"必修", semester:"2023-2024-1", time:"周二 3-4节", location:"教3-205", capacity:45, selected:0, department:"公共课" },
  { id:"C003", name:"程序设计基础（C语言）", teacher:"张伟", credit:3, type:"必修", semester:"2023-2024-1", time:"周三 1-2节", location:"实验楼A-301", capacity:40, selected:0, department:"信息工程学院" },
  { id:"C004", name:"数据结构", teacher:"李明", credit:3.5, type:"必修", semester:"2023-2024-1", time:"周四 5-6节", location:"教2-101", capacity:40, selected:0, department:"信息工程学院" },
  { id:"C005", name:"马克思主义基本原理", teacher:"王芳", credit:2, type:"必修", semester:"2023-2024-1", time:"周五 1-2节", location:"教1-201", capacity:80, selected:0, department:"公共课" },
  { id:"C006", name:"离散数学", teacher:"赵刚", credit:3, type:"必修", semester:"2023-2024-1", time:"周一 5-6节", location:"教2-303", capacity:40, selected:0, department:"信息工程学院" },
  { id:"C007", name:"大学物理（上）", teacher:"周文博", credit:4, type:"必修", semester:"2023-2024-1", time:"周三 3-4节", location:"教1-102", capacity:55, selected:0, department:"公共课" },
  { id:"C008", name:"管理学原理", teacher:"黄丽", credit:2, type:"必修", semester:"2023-2024-1", time:"周二 1-2节", location:"教4-201", capacity:50, selected:0, department:"经济与管理学院" },
  { id:"C009", name:"中国近现代史纲要", teacher:"杨波", credit:2, type:"必修", semester:"2023-2024-1", time:"周四 3-4节", location:"教1-401", capacity:80, selected:0, department:"公共课" },
  { id:"C010", name:"计算机网络", teacher:"陈刚", credit:3, type:"选修", semester:"2023-2024-1", time:"周五 3-4节", location:"实验楼B-202", capacity:35, selected:0, department:"信息工程学院" },
  { id:"C011", name:"心理学导论", teacher:"林小红", credit:2, type:"选修", semester:"2023-2024-1", time:"周一 7-8节", location:"教4-103", capacity:60, selected:0, department:"公共课" },
  { id:"C012", name:"日语入门", teacher:"吴雨桐", credit:2, type:"选修", semester:"2023-2024-1", time:"周三 7-8节", location:"教3-301", capacity:40, selected:0, department:"外国语学院" },
  { id:"C013", name:"Python数据分析", teacher:"刘洋", credit:2, type:"选修", semester:"2023-2024-1", time:"周二 7-8节", location:"实验楼A-201", capacity:30, selected:0, department:"信息工程学院" },
  { id:"C014", name:"书法鉴赏", teacher:"张志远", credit:1.5, type:"选修", semester:"2023-2024-1", time:"周四 7-8节", location:"教5-102", capacity:50, selected:0, department:"公共课" },
  { id:"C015", name:"体育（一）", teacher:"马强", credit:1, type:"必修", semester:"2023-2024-1", time:"周三 5-6节", location:"体育馆", capacity:40, selected:0, department:"公共课" },
];

const presetGrades = [
  { studentId:"20230101001", courseId:"C001", courseName:"高等数学（上）", semester:"2023-2024-1", credit:4, regularScore:85, examScore:78, totalScore:80, gpa:3.0, rank:10 },
  { studentId:"20230101001", courseId:"C002", courseName:"大学英语（一）", semester:"2023-2024-1", credit:3, regularScore:90, examScore:85, totalScore:87, gpa:3.3, rank:5 },
  { studentId:"20230101001", courseId:"C003", courseName:"程序设计基础", semester:"2023-2024-1", credit:3, regularScore:88, examScore:82, totalScore:84, gpa:3.3, rank:8 },
  { studentId:"20230101001", courseId:"C005", courseName:"马克思主义基本原理", semester:"2023-2024-1", credit:2, regularScore:92, examScore:88, totalScore:90, gpa:4.0, rank:3 },
  { studentId:"20230101001", courseId:"C015", courseName:"体育（一）", semester:"2023-2024-1", credit:1, regularScore:95, examScore:90, totalScore:92, gpa:4.0, rank:2 },
  { studentId:"20230101001", courseId:"C004", courseName:"数据结构", semester:"2024-2025-1", credit:3.5, regularScore:80, examScore:75, totalScore:77, gpa:2.7, rank:15 },
  { studentId:"20230101001", courseId:"C006", courseName:"离散数学", semester:"2024-2025-1", credit:3, regularScore:88, examScore:90, totalScore:89, gpa:3.7, rank:4 },
  { studentId:"20230101001", courseId:"C007", courseName:"大学物理（上）", semester:"2024-2025-1", credit:4, regularScore:76, examScore:72, totalScore:74, gpa:2.3, rank:18 },
  { studentId:"20230101002", courseId:"C001", courseName:"高等数学（上）", semester:"2023-2024-1", credit:4, regularScore:78, examScore:82, totalScore:80, gpa:3.0, rank:15 },
  { studentId:"20230101002", courseId:"C002", courseName:"大学英语（一）", semester:"2023-2024-1", credit:3, regularScore:85, examScore:90, totalScore:88, gpa:3.7, rank:3 },
];

const presetExams = [
  { id:"E001", courseId:"C001", courseName:"高等数学（上）", date:"2024-01-15", time:"09:00-11:00", location:"教1-301", seatNo:"A12" },
  { id:"E002", courseId:"C002", courseName:"大学英语（一）", date:"2024-01-16", time:"14:00-16:00", location:"教3-205", seatNo:"B08" },
  { id:"E003", courseId:"C003", courseName:"程序设计基础", date:"2024-01-17", time:"09:00-11:00", location:"实验楼A-301", seatNo:"C15" },
  { id:"E004", courseId:"C005", courseName:"马克思主义基本原理", date:"2024-01-18", time:"14:00-16:00", location:"教1-201", seatNo:"D03" },
  { id:"E005", courseId:"C006", courseName:"离散数学", date:"2024-01-19", time:"09:00-11:00", location:"教2-303", seatNo:"E20" },
  { id:"E006", courseId:"C007", courseName:"大学物理（上）", date:"2024-01-20", time:"14:00-16:00", location:"教1-102", seatNo:"F07" },
  { id:"E007", courseId:"C008", courseName:"管理学原理", date:"2024-01-15", time:"09:00-11:00", location:"教4-201", seatNo:"G11" },
];

const presetNotices = [
  { id:"N001", title:"关于2024年元旦放假安排的通知", content:"根据学校工作安排，2024年元旦放假3天（2023年12月30日至2024年1月1日）。放假期间，各教学楼正常开放。请同学们合理安排学习时间。", date:"2023-12-25", publisher:"教务处", important:true },
  { id:"N002", title:"2023-2024学年第一学期期末考试安排通知", content:"本学期期末考试定于2024年1月15日至1月22日进行。请各位同学登录教务系统查询具体考试安排，并携带学生证和身份证参加考试。考试作弊将按学校规定严肃处理。", date:"2024-01-05", publisher:"教务处", important:true },
  { id:"N003", title:"关于2023-2024学年第二学期选课的通知", content:"2023-2024学年第二学期选课将于2024年2月20日8:00开始，2月25日23:59结束。请同学们按时登录教务系统完成选课。公选课采用先到先得原则，每人限选2门。", date:"2024-02-18", publisher:"教务处", important:true },
  { id:"N004", title:"关于举办第十届大学生程序设计竞赛的通知", content:"为促进计算机程序设计教学，激发学生创新思维，学校决定举办第十届大学生程序设计竞赛。报名时间：2024年3月1日至3月10日。比赛时间：2024年3月20日。欢迎全校同学踊跃报名！", date:"2024-02-28", publisher:"信息工程学院", important:false },
  { id:"N005", title:"关于2024年英语四六级考试报名的通知", content:"2024年上半年全国大学英语四、六级考试将于6月15日进行。报名时间：3月18日8:00至3月25日18:00，请符合报名条件的同学登录CET报名系统完成报名。", date:"2024-03-14", publisher:"教务处", important:true },
  { id:"N006", title:"关于调整部分课程上课教室的通知", content:"因教学楼维修安排，以下课程临时调整上课地点：1. 高等数学（刘建国老师）周二1-2节改为教2-401；2. 大学物理（周文博老师）周四3-4节改为教1-301。恢复时间另行通知。", date:"2024-03-20", publisher:"教务处", important:false },
  { id:"N007", title:"2024年毕业设计（论文）工作安排", content:"2024届毕业生毕业设计（论文）答辩时间定于5月20日-5月30日。请各指导教师和学生按照时间节点完成：5月1日前提交初稿，5月15日前完成定稿，5月20日起正式答辩。", date:"2024-04-01", publisher:"教务处", important:true },
];

// ==================== Turso 数据库连接 ====================
const TURSO_URL = process.env.TURSO_URL || '';
const TURSO_TOKEN = process.env.TURSO_TOKEN || '';

let db;
if (TURSO_URL && TURSO_TOKEN) {
  const { createClient } = require('@libsql/client');
  db = createClient({ url: TURSO_URL, authToken: TURSO_TOKEN });
  console.log('✅ 使用 Turso 云数据库');
} else {
  console.log('⚠️ 未配置 TURSO，使用内存存储');
}

// 内存数据存储（当无 Turso 时使用）
let users = [], students = [], courses = [], grades = [], exams = [], notices = [], myCourses = [];

async function initData() {
  if (db) {
    // 使用 Turso 数据库
    try {
      // 建表
      await db.execute(`
        CREATE TABLE IF NOT EXISTS users (
          username TEXT PRIMARY KEY, password TEXT NOT NULL, role TEXT DEFAULT 'student',
          name TEXT, studentId TEXT UNIQUE, department TEXT, major TEXT, className TEXT,
          gender TEXT, enrollYear TEXT
        )
      `);
      await db.execute(`
        CREATE TABLE IF NOT EXISTS students (
          studentId TEXT PRIMARY KEY, name TEXT, gender TEXT, department TEXT,
          major TEXT, className TEXT, enrollYear TEXT, birthDate TEXT, idCard TEXT,
          phone TEXT, address TEXT, status TEXT DEFAULT '在读'
        )
      `);
      await db.execute(`
        CREATE TABLE IF NOT EXISTS courses (
          id TEXT PRIMARY KEY, name TEXT, teacher TEXT, credit REAL, type TEXT,
          semester TEXT, time TEXT, location TEXT, capacity INTEGER DEFAULT 60,
          selected INTEGER DEFAULT 0, department TEXT
        )
      `);
      await db.execute(`
        CREATE TABLE IF NOT EXISTS grades (
          studentId TEXT, courseId TEXT, courseName TEXT, semester TEXT,
          credit REAL, regularScore REAL, examScore REAL, totalScore REAL,
          gpa REAL, rank INTEGER, PRIMARY KEY (studentId, courseId)
        )
      `);
      await db.execute(`
        CREATE TABLE IF NOT EXISTS exams (
          id TEXT PRIMARY KEY, courseId TEXT, courseName TEXT,
          date TEXT, time TEXT, location TEXT, seatNo TEXT
        )
      `);
      await db.execute(`
        CREATE TABLE IF NOT EXISTS notices (
          id TEXT PRIMARY KEY, title TEXT, content TEXT, date TEXT,
          publisher TEXT, important INTEGER DEFAULT 0
        )
      `);
      await db.execute(`
        CREATE TABLE IF NOT EXISTS my_courses (
          studentId TEXT, courseId TEXT, PRIMARY KEY (studentId, courseId)
        )
      `);

      // 检查是否已有数据（首次初始化）
      const count = await db.execute('SELECT COUNT(*) as cnt FROM users');
      if (count.rows[0].cnt === 0) {
        for (const u of presetUsers) {
          const hpw = u.password.startsWith('$2a$') ? u.password : bcrypt.hashSync(u.password, 10);
          await db.execute({
            sql: 'INSERT OR IGNORE INTO users VALUES (?,?,?,?,?,?,?,?,?,?)',
            args: [u.username, hpw, u.role, u.name, u.studentId, u.department, u.major, u.className, u.gender, u.enrollYear]
          });
        }
        for (const s of presetStudents) {
          await db.execute({
            sql: 'INSERT OR IGNORE INTO students VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
            args: [s.studentId, s.name, s.gender, s.department, s.major, s.className, s.enrollYear, s.birthDate, s.idCard, s.phone, s.address, s.status]
          });
        }
        for (const c of presetCourses) {
          await db.execute({
            sql: 'INSERT OR IGNORE INTO courses VALUES (?,?,?,?,?,?,?,?,?,?,?)',
            args: [c.id, c.name, c.teacher, c.credit, c.type, c.semester, c.time, c.location, c.capacity, c.selected, c.department]
          });
        }
        for (const g of presetGrades) {
          await db.execute({
            sql: 'INSERT OR IGNORE INTO grades VALUES (?,?,?,?,?,?,?,?,?,?)',
            args: [g.studentId, g.courseId, g.courseName, g.semester, g.credit, g.regularScore, g.examScore, g.totalScore, g.gpa, g.rank]
          });
        }
        for (const e of presetExams) {
          await db.execute({
            sql: 'INSERT OR IGNORE INTO exams VALUES (?,?,?,?,?,?,?)',
            args: [e.id, e.courseId, e.courseName, e.date, e.time, e.location, e.seatNo]
          });
        }
        for (const n of presetNotices) {
          await db.execute({
            sql: 'INSERT OR IGNORE INTO notices VALUES (?,?,?,?,?,?)',
            args: [n.id, n.title, n.content, n.date, n.publisher, n.important ? 1 : 0]
          });
        }
        console.log('✅ 预设数据已导入 Turso');
      }
    } catch (err) {
      console.error('Turso 初始化失败，降级为内存:', err.message);
      db = null;
    }
  }

  if (!db) {
    // 内存存储
    users = JSON.parse(JSON.stringify(presetUsers));
    students = JSON.parse(JSON.stringify(presetStudents));
    courses = JSON.parse(JSON.stringify(presetCourses));
    grades = JSON.parse(JSON.stringify(presetGrades));
    exams = JSON.parse(JSON.stringify(presetExams));
    notices = JSON.parse(JSON.stringify(presetNotices));
    myCourses = [];
    users.forEach(u => {
      if (!u.password.startsWith('$2a$')) u.password = bcrypt.hashSync(u.password, 10);
    });
  }
}

// ==================== 数据库查询辅助 ====================
async function dbAll(table, where = '', params = []) {
  if (!db) {
    const data = { users, students, courses, grades, exams, notices, myCourses };
    let arr = data[table] || [];
    return arr;
  }
  try {
    const sql = where ? `SELECT * FROM ${table} WHERE ${where}` : `SELECT * FROM ${table}`;
    const result = await db.execute({ sql, args: params });
    // 将 important 0/1 转 bool
    return result.rows.map(r => ({ ...r, important: r.important === 1 || r.important === true }));
  } catch (e) { return []; }
}

async function dbGet(table, where, params = []) {
  if (!db) {
    const data = { users, students, courses, grades, exams, notices, myCourses };
    let arr = data[table] || [];
    // 简单 KV 查找
    const [key, val] = where.split(' = ?');
    const cleanKey = key.replace(/"/g, '').trim();
    return arr.find(x => x[cleanKey] == params[0]) || null;
  }
  try {
    const result = await db.execute({ sql: `SELECT * FROM ${table} WHERE ${where} LIMIT 1`, args: params });
    if (result.rows.length === 0) return null;
    const r = result.rows[0];
    r.important = r.important === 1 || r.important === true;
    return r;
  } catch (e) { return null; }
}

async function dbInsert(table, obj) {
  if (!db) {
    const data = { users, students, courses, grades, exams, notices, myCourses };
    data[table].push(obj);
    return;
  }
  try {
    const keys = Object.keys(obj);
    const vals = Object.values(obj);
    const placeholders = keys.map(() => '?').join(',');
    await db.execute({ sql: `INSERT OR REPLACE INTO ${table} (${keys.join(',')}) VALUES (${placeholders})`, args: vals });
  } catch (e) { }
}

async function dbDelete(table, where, params = []) {
  if (!db) {
    const data = { users, students, courses, grades, exams, notices, myCourses };
    const [key, val] = where.split(' = ?');
    const cleanKey = key.replace(/"/g, '').trim();
    const idx = data[table].findIndex(x => x[cleanKey] == params[0]);
    if (idx >= 0) data[table].splice(idx, 1);
    return;
  }
  try {
    await db.execute({ sql: `DELETE FROM ${table} WHERE ${where}`, args: params });
  } catch (e) { }
}

async function dbUpdate(table, setClause, where, params = []) {
  if (!db) return;
  try {
    await db.execute({ sql: `UPDATE ${table} SET ${setClause} WHERE ${where}`, args: params });
  } catch (e) { }
}

// ==================== API 路由 ====================

// 登录
app.post('/api/login', (req, res) => {
  const ip = (req.headers['x-forwarded-for'] || req.ip || '0').split(',')[0].trim();

  // 限流检查
  if (!checkLoginLimit(ip)) {
    return res.status(429).json({ success: false, message: '登录尝试过多，请15分钟后再试' });
  }

  const { username, password } = req.body;
  const uname = sanitize(username);
  if (!uname || !password) return res.status(400).json({ success: false, message: '请输入账号和密码' });

  // 查找用户
  dbGet('users', 'username = ?', [uname]).then(user => {
    if (!user) {
      return res.json({ success: false, message: '账号不存在' });
    }
    const valid = bcrypt.compareSync(password, user.password);
    if (!valid) {
      return res.json({ success: false, message: '密码错误' });
    }
    recordLoginSuccess(ip);
    res.json({
      success: true,
      user: {
        username: user.username, name: user.name, role: user.role,
        studentId: user.studentId, department: user.department,
        major: user.major, className: user.className, gender: user.gender,
        enrollYear: user.enrollYear
      }
    });
  }).catch(() => res.json({ success: false, message: '系统错误' }));
});

// 注册
app.post('/api/register', async (req, res) => {
  const { username, password, name, department, major, gender, enrollYear } = req.body;
  const uname = sanitize(username);
  const rname = sanitize(name);
  if (!uname || !password || !rname) return res.status(400).json({ success: false, message: '请填写必要信息' });
  if (password.length < 6) return res.json({ success: false, message: '密码至少6位' });

  const exist = await dbGet('users', 'username = ?', [uname]);
  if (exist) return res.json({ success: false, message: '该账号已存在' });

  const hpw = bcrypt.hashSync(password, 10);
  await dbInsert('users', {
    username: uname, password: hpw, role: 'student',
    name: rname, studentId: uname,
    department: sanitize(department) || '', major: sanitize(major) || '',
    className: '', gender: gender === '女' ? '女' : '男',
    enrollYear: sanitize(enrollYear) || '2024'
  });
  await dbInsert('students', {
    studentId: uname, name: rname, gender: gender === '女' ? '女' : '男',
    department: sanitize(department) || '', major: sanitize(major) || '',
    className: '', enrollYear: sanitize(enrollYear) || '2024',
    birthDate: '', idCard: '', phone: '', address: '', status: '在读'
  });
  res.json({ success: true, message: '注册成功！请登录' });
});

// 修改密码
app.post('/api/change-password', async (req, res) => {
  const { username, oldPassword, newPassword } = req.body;
  if (!newPassword || newPassword.length < 6) return res.json({ success: false, message: '新密码至少6位' });
  const user = await dbGet('users', 'username = ?', [sanitize(username)]);
  if (!user) return res.json({ success: false, message: '用户不存在' });
  if (!bcrypt.compareSync(oldPassword, user.password)) return res.json({ success: false, message: '原密码错误' });
  const hpw = bcrypt.hashSync(newPassword, 10);
  await dbUpdate('users', 'password = ?', 'username = ?', [hpw, sanitize(username)]);
  res.json({ success: true, message: '密码修改成功' });
});

// 学生信息
app.get('/api/student/:sid', async (req, res) => {
  const s = await dbGet('students', 'studentId = ?', [req.params.sid]);
  const u = await dbGet('users', 'studentId = ?', [req.params.sid]);
  res.json({ success: true, data: { ...(s || {}), ...(u ? { department: u.department, major: u.major, className: u.className, enrollYear: u.enrollYear } : {}) } });
});

// 课程
app.get('/api/courses', async (req, res) => {
  const data = await dbAll('courses');
  res.json({ success: true, data });
});

// 课表
app.get('/api/schedule/:sid', async (req, res) => {
  const u = await dbGet('users', 'studentId = ?', [req.params.sid]);
  const all = await dbAll('courses');
  const dept = u ? u.department : '';
  const data = all.filter(c => c.type === '必修' ? (c.department === dept || c.department === '公共课') : true);
  res.json({ success: true, data });
});

// 成绩
app.get('/api/grades/:sid', async (req, res) => {
  const all = await dbAll('grades');
  const g = all.filter(x => x.studentId === req.params.sid);
  const semesters = [...new Set(g.map(x => x.semester))].sort().reverse();
  const summary = {};
  semesters.forEach(sem => {
    const sg = g.filter(x => x.semester === sem);
    const tc = sg.reduce((s, x) => s + x.credit, 0);
    const wg = sg.reduce((s, x) => s + x.gpa * x.credit, 0);
    summary[sem] = { totalCredit: tc, avgGPA: tc ? (wg / tc).toFixed(2) : 0 };
  });
  res.json({ success: true, data: g, semesters, summary });
});

// 选课
app.post('/api/select-course', async (req, res) => {
  const { studentId, courseId } = req.body;
  const c = await dbGet('courses', 'id = ?', [courseId]);
  if (!c) return res.json({ success: false, message: '课程不存在' });
  if (c.selected >= c.capacity) return res.json({ success: false, message: '课程已满' });

  await dbUpdate('courses', 'selected = selected + 1', 'id = ?', [courseId]);

  const existing = await dbAll('my_courses');
  if (!existing.find(x => x.studentId === studentId && x.courseId === courseId)) {
    await dbInsert('my_courses', { studentId, courseId });
  }
  res.json({ success: true, message: '选课成功！' });
});

// 退课
app.post('/api/drop-course', async (req, res) => {
  const { studentId, courseId } = req.body;
  const c = await dbGet('courses', 'id = ?', [courseId]);
  if (c && c.selected > 0) {
    await dbUpdate('courses', 'selected = selected - 1', 'id = ?', [courseId]);
  }
  await dbDelete('my_courses', 'studentId = ? AND courseId = ?', [studentId, courseId]);
  res.json({ success: true, message: '退课成功！' });
});

// 我的选课
app.get('/api/my-courses/:sid', async (req, res) => {
  const mc = await dbAll('my_courses');
  const all = await dbAll('courses');
  const my = mc.filter(x => x.studentId === req.params.sid);
  res.json({ success: true, data: my.map(x => all.find(c => c.id === x.courseId)).filter(Boolean) });
});

// 通知
app.get('/api/notices', async (req, res) => {
  const data = await dbAll('notices');
  res.json({ success: true, data: data.sort((a, b) => b.date.localeCompare(a.date)) });
});

// 考试
app.get('/api/exams/:sid', async (req, res) => {
  const data = await dbAll('exams');
  res.json({ success: true, data });
});

// ==================== 管理端 API（需要 admin 权限） ====================
app.get('/api/admin/users', adminAuth, async (req, res) => {
  const data = await dbAll('users');
  res.json({ success: true, data: data.map(u => ({ ...u, password: undefined })) });
});

app.delete('/api/admin/users/:username', adminAuth, async (req, res) => {
  await dbDelete('users', 'username = ?', [req.params.username]);
  await dbDelete('students', 'studentId = ?', [req.params.username]);
  await dbDelete('grades', 'studentId = ?', [req.params.username]);
  res.json({ success: true, message: '删除成功' });
});

app.post('/api/admin/courses', adminAuth, async (req, res) => {
  await dbInsert('courses', req.body);
  res.json({ success: true, message: '添加成功' });
});

app.put('/api/admin/courses/:id', adminAuth, async (req, res) => {
  const c = await dbGet('courses', 'id = ?', [req.params.id]);
  if (!c) return res.json({ success: false, message: '不存在' });
  // 更新所有字段
  const fields = req.body;
  const setParts = Object.keys(fields).map(k => `${k} = ?`).join(', ');
  const vals = Object.values(fields);
  await dbUpdate('courses', setParts, 'id = ?', [...vals, req.params.id]);
  res.json({ success: true, message: '更新成功' });
});

app.delete('/api/admin/courses/:id', adminAuth, async (req, res) => {
  await dbDelete('courses', 'id = ?', [req.params.id]);
  res.json({ success: true, message: '删除成功' });
});

app.get('/api/admin/students', adminAuth, async (req, res) => {
  const data = await dbAll('students');
  res.json({ success: true, data });
});

app.get('/api/admin/grades', adminAuth, async (req, res) => {
  const data = await dbAll('grades');
  res.json({ success: true, data });
});

app.post('/api/admin/grades', adminAuth, async (req, res) => {
  const { studentId, courseId } = req.body;
  const all = await dbAll('grades');
  const exist = all.find(g => g.studentId === studentId && g.courseId === courseId);
  if (exist) {
    const fields = req.body;
    const setParts = Object.keys(fields).map(k => `${k} = ?`).join(', ');
    const vals = Object.values(fields);
    await dbUpdate('grades', setParts, 'studentId = ? AND courseId = ?', [...vals, studentId, courseId]);
  } else {
    await dbInsert('grades', req.body);
  }
  res.json({ success: true, message: '保存成功' });
});

app.post('/api/admin/notices', adminAuth, async (req, res) => {
  if (req.body.important === true || req.body.important === 'true') req.body.important = 1;
  else req.body.important = 0;
  await dbInsert('notices', req.body);
  res.json({ success: true, message: '发布成功' });
});

app.delete('/api/admin/notices/:id', adminAuth, async (req, res) => {
  await dbDelete('notices', 'id = ?', [req.params.id]);
  res.json({ success: true, message: '删除成功' });
});

app.post('/api/admin/exams', adminAuth, async (req, res) => {
  await dbInsert('exams', req.body);
  res.json({ success: true, message: '添加成功' });
});

app.put('/api/admin/exams/:id', adminAuth, async (req, res) => {
  const fields = req.body;
  const setParts = Object.keys(fields).map(k => `${k} = ?`).join(', ');
  const vals = Object.values(fields);
  await dbUpdate('exams', setParts, 'id = ?', [...vals, req.params.id]);
  res.json({ success: true, message: '更新成功' });
});

app.delete('/api/admin/exams/:id', adminAuth, async (req, res) => {
  await dbDelete('exams', 'id = ?', [req.params.id]);
  res.json({ success: true, message: '删除成功' });
});

// ==================== 静态文件 ====================
app.use(express.static(path.join(__dirname, '..')));
app.get(/^\/(?!api\/).*/, (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'index.html'));
});

// 导出给 Vercel
module.exports = app;

// 本地启动
if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  initData();
  app.listen(PORT, () => {
    console.log(`✅ 教务系统后端已启动: http://localhost:${PORT}`);
    console.log(`📋 管理员: admin / admin123`);
    console.log(`📋 学生: 20230101001 / 123456`);
  });
} else {
  initData();
}
