const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const https = require('https');

// 微信通知：通过 Server酱 推送消息到微信
const SERVERCHAN_KEY = process.env.SERVERCHAN_KEY || ''; // 在 Vercel 环境变量中设置
function pushWechat(title, desp) {
  if (!SERVERCHAN_KEY) return;
  const postData = JSON.stringify({ title, desp: desp.replace(/\n/g, '\n\n') });
  const req = https.request({
    hostname: 'sctapi.ftqq.com',
    path: `/${SERVERCHAN_KEY}.send`,
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(postData) }
  }, (res) => { res.on('data', () => {}); });
  req.on('error', (e) => { console.error('Wechat push failed:', e.message); });
  req.write(postData);
  req.end();
}
const nodemailer = require('nodemailer');

// QQ邮箱SMTP配置
const SMTP_CONFIG = {
  host: 'smtp.qq.com',
  port: 465,
  secure: true,
  auth: { user: '2129474226@qq.com', pass: process.env.QQ_SMTP_PASS || '' }
};

// 邮件发送
async function sendEmail(to, subject, html) {
  if (!SMTP_CONFIG.auth.pass) return false;
  try {
    const transporter = nodemailer.createTransport(SMTP_CONFIG);
    await transporter.sendMail({ from: SMTP_CONFIG.auth.user, to, subject, html });
    return true;
  } catch (e) { console.error('邮件发送失败:', e.message); return false; }
}

const app = express();

// ==================== 安全中间件 ====================
app.use(express.json({ limit: '2mb' }));
app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    callback(null, true);
  },
  credentials: true
}));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

// ==================== 登录限流 ====================
const loginAttempts = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of loginAttempts) {
    if (now - v.firstAttempt > 900000) loginAttempts.delete(k);
  }
}, 60000);

function checkLoginLimit(ip) {
  const now = Date.now();
  let r = loginAttempts.get(ip);
  if (!r || now - r.firstAttempt > 900000) {
    loginAttempts.set(ip, { count: 1, firstAttempt: now, locked: false, lockedUntil: 0 });
    return true;
  }
  if (r.locked && now < r.lockedUntil) return false;
  if (r.locked && now >= r.lockedUntil) {
    loginAttempts.set(ip, { count: 1, firstAttempt: now, locked: false, lockedUntil: 0 });
    return true;
  }
  r.count++;
  if (r.count > 10) { r.locked = true; r.lockedUntil = now + 900000; return false; }
  return true;
}
function recordLoginSuccess(ip) { loginAttempts.delete(ip); }

// ==================== Token 管理 ====================
// crypto 已在顶部导入
const activeTokens = new Map(); // token -> { username, role, createdAt }

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

// 管理员权限校验：从请求头的 Authorization 读取 Bearer token
function adminAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: '请先登录管理员账号' });
  }
  const token = authHeader.slice(7);
  const session = activeTokens.get(token);
  if (!session || session.role !== 'admin') {
    return res.status(403).json({ success: false, message: '无管理员权限' });
  }
  req.adminUser = session;
  next();
}

// 教师权限校验
function teacherAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: '请先登录' });
  }
  const token = authHeader.slice(7);
  const session = activeTokens.get(token);
  if (!session || (session.role !== 'teacher' && session.role !== 'admin')) {
    return res.status(403).json({ success: false, message: '无权限' });
  }
  req.teacherUser = session;
  next();
}

// 学生权限校验
function studentAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: '请先登录' });
  }
  const token = authHeader.slice(7);
  const session = activeTokens.get(token);
  if (!session) return res.status(401).json({ success: false, message: '登录已过期' });
  req.currentUser = session;
  next();
}

// ==================== 输入过滤 ====================
function sanitize(str) {
  if (typeof str !== 'string') return str;
  return str.replace(/[<>"'&]/g, '').trim();
}

// ==================== 预置数据 ====================
const presetUsers = [
  { username:"admin", password:"admin123", role:"admin", name:"系统管理员", studentId:"000001", department:"教务处", major:"", className:"", gender:"男", enrollYear:"2020" },
  { username:"t001", password:"123456", role:"teacher", name:"刘建国", studentId:"T001", department:"公共课部", major:"数学", className:"", gender:"男", enrollYear:"2010" },
  { username:"t002", password:"123456", role:"teacher", name:"陈美玲", studentId:"T002", department:"公共课部", major:"英语", className:"", gender:"女", enrollYear:"2012" },
  { username:"t003", password:"123456", role:"teacher", name:"张伟", studentId:"T003", department:"信息工程学院", major:"计算机科学", className:"", gender:"男", enrollYear:"2015" },
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

// 学校配置
let schoolConfig = {
  name: "H大学",
  fullName: "H大学",
  motto: "厚德载物 · 博学笃行 · 求实创新",
  address: "湖北省孝感市学院路158号",
  phone: "(0712)2345612",
  enrollmentPhone: "18695085845",
  email: "2129474226@qq.com",
  copyright: "Copyright © 2024 H大学 All Rights Reserved",
  icp: "鄂ICP备06000924号",
  studentCount: "15000",
  teacherCount: "800",
  campusArea: "1200",
  departmentCount: "15",
  majorCount: "50",
  historyYears: "20",
  // 学校概况内容（支持HTML）
  aboutTitle: "关于 H 大学",
  aboutContent: "<p>H大学是一所综合性全日制普通本科高等院校，坐落于美丽的孝感市。学校秉承'厚德载物、博学笃行'的校训，致力于培养具有创新精神和实践能力的高素质应用型人才。</p><p>学校设有信息工程学院、经济与管理学院、文学与新闻传播学院、外国语学院、机电工程学院、生物与化学学院、艺术与设计学院等十余个教学单位，涵盖工、管、文、理、艺等多个学科门类。</p><p>学校现有在校学生15000余人，教职工800余人，校园占地面积1200余亩，建筑面积40余万平方米，教学科研仪器设备总值超过1.5亿元。</p>",
  // 统计数据
  stats: { departments:"15", majors:"50+", students:"15000+", teachers:"800+", area:"1200", years:"20+" },
  // 首页新闻（管理员可编辑）
  homeNews: [
    { title:"H大学2026年教学工作会议顺利召开", excerpt:"会议总结了上一年度教学工作成果，部署了新学期的重点任务...", date:"2026-07-15", icon:"fa-newspaper" },
    { title:"我校学子在全国大学生程序设计竞赛中荣获一等奖", excerpt:"来自信息工程学院的团队经过激烈角逐，从200余支队伍中脱颖而出...", date:"2026-07-12", icon:"fa-trophy" },
    { title:"H大学与多家知名企业签署校企合作协议", excerpt:"双方将在人才培养、科研合作、实习就业等方面展开深度合作...", date:"2026-07-08", icon:"fa-handshake" },
    { title:"2026届毕业生典礼隆重举行", excerpt:"三千余名毕业生身着学位服，共同见证这一庄严而温馨的时刻...", date:"2026-06-28", icon:"fa-graduation-cap" }
  ]
};

// 友情链接
let friendLinks = [
  { name: "教育部", url: "https://www.moe.gov.cn" },
  { name: "湖北省教育厅", url: "https://jyt.hubei.gov.cn" },
  { name: "学信网", url: "https://www.chsi.com.cn" },
  { name: "湖北招生信息网", url: "https://zsxx.e21.cn" }
];

// 操作日志
let operationLogs = [];

// 在线用户追踪 + 验证码 + 留言板 + 打赏
let onlineUsers = new Map(); // userId -> { lastActive, ip, userAgent }
let emailCodes = new Map(); // email -> { code, expires, userId }
let messages = []; // { id, userId, userName, content, time }
let donateInfo = { qrCodeUrl: '', alipayUrl: '', wechatUrl: '', thankYouMsg: '感谢您的支持！' };

// 清理过期在线用户（5分钟无活动视为离线）
setInterval(() => {
  const now = Date.now();
  for (const [uid, v] of onlineUsers) {
    if (now - v.lastActive > 300000) onlineUsers.delete(uid);
  }
  // 清理过期验证码（10分钟）
  for (const [email, v] of emailCodes) {
    if (now > v.expires) emailCodes.delete(email);
  }
}, 60000);

// ==================== 内存存储（初始化从预设数据拷贝） ====================
let users = [], students = [], courses = [], grades = [], exams = [], notices = [], myCourses = [];

function initData() {
  users = presetUsers.map(u => ({
    ...u,
    password: u.password.startsWith('$2a$') ? u.password : bcrypt.hashSync(u.password, 10)
  }));
  students = JSON.parse(JSON.stringify(presetStudents));
  courses = JSON.parse(JSON.stringify(presetCourses));
  grades = JSON.parse(JSON.stringify(presetGrades));
  exams = JSON.parse(JSON.stringify(presetExams));
  notices = JSON.parse(JSON.stringify(presetNotices));
  myCourses = [];
}
initData();

// 辅助函数
function findOne(arr, key, val) { return arr.find(x => x[key] == val) || null; }
function findAll(arr, key, val) { return arr.filter(x => x[key] == val); }
function removeOne(arr, key, val) {
  const idx = arr.findIndex(x => x[key] == val);
  if (idx >= 0) arr.splice(idx, 1);
}
function paginate(arr, page = 1, pageSize = 20) {
  const start = (page - 1) * pageSize;
  const items = arr.slice(start, start + pageSize);
  return { items, total: arr.length, page, pageSize, totalPages: Math.ceil(arr.length / pageSize) };
}

// ==================== 公开 API ====================

// 登录
app.post('/api/login', (req, res) => {
  const ip = (req.headers['x-forwarded-for'] || req.ip || '0').split(',')[0].trim();
  if (!checkLoginLimit(ip)) {
    return res.status(429).json({ success: false, message: '登录尝试过多，请15分钟后再试' });
  }
  const { username, password } = req.body;
  const uname = sanitize(username);
  if (!uname || !password) return res.status(400).json({ success: false, message: '请输入账号和密码' });

  const user = findOne(users, 'username', uname);
  if (!user) return res.json({ success: false, message: '账号不存在' });
  const valid = bcrypt.compareSync(password, user.password);
  if (!valid) return res.json({ success: false, message: '密码错误' });

  recordLoginSuccess(ip);
  const token = generateToken();
  activeTokens.set(token, {
    username: user.username, role: user.role, name: user.name,
    studentId: user.studentId, department: user.department, createdAt: Date.now()
  });
  // 记录在线
  onlineUsers.set(user.username, { lastActive: Date.now(), ip, userAgent: req.headers['user-agent'] || '', name: user.name, role: user.role });
  // 清理过期 token（24小时）
  const now = Date.now();
  for (const [k, v] of activeTokens) {
    if (now - v.createdAt > 86400000) activeTokens.delete(k);
  }

  res.json({
    success: true,
    token,
    user: {
      username: user.username, name: user.name, role: user.role,
      studentId: user.studentId, department: user.department,
      major: user.major, className: user.className, gender: user.gender,
      enrollYear: user.enrollYear, email: user.email || ''
    }
  });
});

// 注册
app.post('/api/register', (req, res) => {
  const { username, password, name, department, major, gender, enrollYear, email } = req.body;
  const uname = sanitize(username);
  const rname = sanitize(name);
  // 学号格式校验：必须11位数字
  if (!uname || !/^\d{11}$/.test(uname)) return res.status(400).json({ success: false, message: '学号必须为11位数字，如 20230101001' });
  if (!password || password.length < 6) return res.json({ success: false, message: '密码至少6位' });
  if (!rname) return res.status(400).json({ success: false, message: '请填写必要信息' });
  if (findOne(users, 'username', uname)) return res.json({ success: false, message: '该账号已存在' });

  users.push({
    username: uname, password: bcrypt.hashSync(password, 10), role: 'student',
    name: rname, studentId: uname,
    department: sanitize(department) || '', major: sanitize(major) || '',
    className: '', gender: gender === '女' ? '女' : '男',
    enrollYear: sanitize(enrollYear) || uname.slice(0, 4), email: sanitize(email) || ''
  });
  students.push({
    studentId: uname, name: rname, gender: gender === '女' ? '女' : '男',
    department: sanitize(department) || '', major: sanitize(major) || '',
    className: '', enrollYear: sanitize(enrollYear) || '2024',
    birthDate: '', idCard: '', phone: '', address: '', status: '在读'
  });

  // 微信通知管理员（通过Server酱）
  pushWechat('H大学教务系统 - 新用户注册', `姓名：${rname}\n学号：${uname}\n院系：${sanitize(department) || '未填写'}\n邮箱：${sanitize(email) || '未填写'}\n时间：${new Date().toLocaleString('zh-CN')}`);

  res.json({ success: true, message: '注册成功！请登录' });
});

// 修改密码（需要登录）
app.post('/api/change-password', (req, res) => {
  const { username, oldPassword, newPassword, token } = req.body;
  const session = activeTokens.get(token);
  if (!session || session.username !== sanitize(username)) {
    return res.status(401).json({ success: false, message: '请先登录' });
  }
  if (!newPassword || newPassword.length < 6) return res.json({ success: false, message: '新密码至少6位' });
  const user = findOne(users, 'username', sanitize(username));
  if (!user) return res.json({ success: false, message: '用户不存在' });
  if (!bcrypt.compareSync(oldPassword, user.password)) return res.json({ success: false, message: '原密码错误' });
  user.password = bcrypt.hashSync(newPassword, 10);
  res.json({ success: true, message: '密码修改成功' });
});

// 学校配置
app.get('/api/config', (req, res) => res.json({ success: true, data: schoolConfig }));

// 学生端 API
app.get('/api/courses', (req, res) => {
  const { page, pageSize, search, type, department } = req.query;
  let list = [...courses];
  if (search) {
    const s = search.toLowerCase();
    list = list.filter(c => c.name.toLowerCase().includes(s) || c.teacher.toLowerCase().includes(s) || c.id.toLowerCase().includes(s));
  }
  if (type) list = list.filter(c => c.type === type);
  if (department) list = list.filter(c => c.department === department);
  res.json({ success: true, ...paginate(list, parseInt(page) || 1, parseInt(pageSize) || 50) });
});

app.get('/api/notices', (req, res) => {
  const sorted = [...notices].sort((a, b) => b.date.localeCompare(a.date));
  res.json({ success: true, data: sorted.slice(0, 20) });
});

app.get('/api/exams/:sid', (req, res) => res.json({ success: true, data: exams }));

app.get('/api/grades/:sid', (req, res) => {
  const g = findAll(grades, 'studentId', req.params.sid);
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

app.get('/api/schedule/:sid', (req, res) => {
  const u = findOne(users, 'studentId', req.params.sid);
  const dept = u ? u.department : '';
  const data = courses.filter(c => c.type === '必修' ? (c.department === dept || c.department === '公共课') : true);
  res.json({ success: true, data });
});

app.get('/api/student/:sid', (req, res) => {
  const s = findOne(students, 'studentId', req.params.sid) || {};
  const u = findOne(users, 'studentId', req.params.sid) || {};
  res.json({ success: true, data: { ...s, ...(u ? { department: u.department, major: u.major, className: u.className, enrollYear: u.enrollYear } : {}) } });
});

// 选课/退课
app.post('/api/select-course', (req, res) => {
  const { studentId, courseId } = req.body;
  const c = findOne(courses, 'id', courseId);
  if (!c) return res.json({ success: false, message: '课程不存在' });
  if (c.selected >= c.capacity) return res.json({ success: false, message: '课程已满' });
  c.selected++;
  if (!myCourses.find(x => x.studentId === studentId && x.courseId === courseId)) {
    myCourses.push({ studentId, courseId });
  }
  res.json({ success: true, message: '选课成功！' });
});

app.post('/api/drop-course', (req, res) => {
  const { studentId, courseId } = req.body;
  const c = findOne(courses, 'id', courseId);
  if (c && c.selected > 0) c.selected--;
  myCourses = myCourses.filter(x => !(x.studentId === studentId && x.courseId === courseId));
  res.json({ success: true, message: '退课成功！' });
});

app.get('/api/my-courses/:sid', (req, res) => {
  const my = myCourses.filter(x => x.studentId === req.params.sid);
  res.json({ success: true, data: my.map(x => findOne(courses, 'id', x.courseId)).filter(Boolean) });
});

// ==================== 教师端 API ====================
app.get('/api/teacher/courses', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ success: false, message: '请先登录' });
  const token = authHeader.slice(7);
  const session = activeTokens.get(token);
  if (!session || (session.role !== 'teacher' && session.role !== 'admin')) return res.status(403).json({ success: false, message: '无权限' });

  const myCoursesList = courses.filter(c => c.teacher === session.name);
  res.json({ success: true, data: myCoursesList });
});

app.get('/api/teacher/course-students/:courseId', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ success: false, message: '请先登录' });
  const token = authHeader.slice(7);
  const session = activeTokens.get(token);
  if (!session || (session.role !== 'teacher' && session.role !== 'admin')) return res.status(403).json({ success: false, message: '无权限' });

  const courseStudents = myCourses.filter(x => x.courseId === req.params.courseId);
  const studentList = courseStudents.map(cs => {
    const s = findOne(students, 'studentId', cs.studentId);
    const g = grades.find(x => x.studentId === cs.studentId && x.courseId === req.params.courseId);
    return { ...(s || {}), grade: g || null };
  });
  res.json({ success: true, data: studentList });
});

app.post('/api/teacher/grades', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ success: false, message: '请先登录' });
  const token = authHeader.slice(7);
  const session = activeTokens.get(token);
  if (!session || (session.role !== 'teacher' && session.role !== 'admin')) return res.status(403).json({ success: false, message: '无权限' });

  const { studentId, courseId, courseName, semester, credit, regularScore, examScore, totalScore, gpa, rank } = req.body;
  const idx = grades.findIndex(g => g.studentId === studentId && g.courseId === courseId);
  if (idx >= 0) {
    Object.assign(grades[idx], req.body);
  } else {
    grades.push({ studentId, courseId, courseName, semester, credit, regularScore: regularScore || 0, examScore: examScore || 0, totalScore: totalScore || 0, gpa: gpa || 0, rank: rank || 0 });
  }
  res.json({ success: true, message: '成绩录入成功' });
});

// ==================== 管理端 API（需 admin token） ====================

// 管理端获取所有数据（带分页搜索）
app.get('/api/admin/users', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ success: false, message: '请先登录' });
  const token = authHeader.slice(7);
  const session = activeTokens.get(token);
  if (!session || session.role !== 'admin') return res.status(403).json({ success: false, message: '无管理员权限' });

  const { page, pageSize, search, role } = req.query;
  let list = users.map(u => ({ ...u, password: undefined }));
  if (search) { const s = search.toLowerCase(); list = list.filter(u => u.name.toLowerCase().includes(s) || u.username.toLowerCase().includes(s) || u.department.toLowerCase().includes(s)); }
  if (role) list = list.filter(u => u.role === role);
  res.json({ success: true, ...paginate(list, parseInt(page) || 1, parseInt(pageSize) || 20) });
});

app.get('/api/admin/students', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ success: false, message: '请先登录' });
  const token = authHeader.slice(7);
  const session = activeTokens.get(token);
  if (!session || session.role !== 'admin') return res.status(403).json({ success: false, message: '无管理员权限' });

  const { page, pageSize, search, department } = req.query;
  let list = [...students];
  if (search) { const s = search.toLowerCase(); list = list.filter(st => st.name.toLowerCase().includes(s) || st.studentId.toLowerCase().includes(s) || st.major.toLowerCase().includes(s)); }
  if (department) list = list.filter(st => st.department === department);
  res.json({ success: true, ...paginate(list, parseInt(page) || 1, parseInt(pageSize) || 20) });
});

app.get('/api/admin/grades', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ success: false, message: '请先登录' });
  const token = authHeader.slice(7);
  const session = activeTokens.get(token);
  if (!session || session.role !== 'admin') return res.status(403).json({ success: false, message: '无管理员权限' });

  const { page, pageSize, search, semester } = req.query;
  let list = [...grades];
  if (search) { const s = search.toLowerCase(); list = list.filter(g => g.studentId.toLowerCase().includes(s) || g.courseName.toLowerCase().includes(s)); }
  if (semester) list = list.filter(g => g.semester === semester);
  res.json({ success: true, ...paginate(list, parseInt(page) || 1, parseInt(pageSize) || 30) });
});

// 管理端 CRUD
app.delete('/api/admin/users/:username', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ success: false, message: '请先登录' });
  const token = authHeader.slice(7);
  const session = activeTokens.get(token);
  if (!session || session.role !== 'admin') return res.status(403).json({ success: false, message: '无管理员权限' });

  removeOne(users, 'username', req.params.username);
  removeOne(students, 'studentId', req.params.username);
  grades = grades.filter(g => g.studentId !== req.params.username);
  operationLogs.push({ time: new Date().toISOString(), admin: session.name, action: '删除用户', target: req.params.username });
  res.json({ success: true, message: '删除成功' });
});

app.post('/api/admin/courses', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ success: false, message: '请先登录' });
  const token = authHeader.slice(7);
  const session = activeTokens.get(token);
  if (!session || session.role !== 'admin') return res.status(403).json({ success: false, message: '无管理员权限' });

  courses.push({ ...req.body, selected: req.body.selected || 0 });
  operationLogs.push({ time: new Date().toISOString(), admin: session.name, action: '添加课程', target: req.body.id });
  res.json({ success: true, message: '添加成功' });
});

app.put('/api/admin/courses/:id', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ success: false, message: '请先登录' });
  const token = authHeader.slice(7);
  const session = activeTokens.get(token);
  if (!session || session.role !== 'admin') return res.status(403).json({ success: false, message: '无管理员权限' });

  const c = findOne(courses, 'id', req.params.id);
  if (!c) return res.json({ success: false, message: '不存在' });
  Object.assign(c, req.body);
  operationLogs.push({ time: new Date().toISOString(), admin: session.name, action: '编辑课程', target: req.params.id });
  res.json({ success: true, message: '更新成功' });
});

app.delete('/api/admin/courses/:id', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ success: false, message: '请先登录' });
  const token = authHeader.slice(7);
  const session = activeTokens.get(token);
  if (!session || session.role !== 'admin') return res.status(403).json({ success: false, message: '无管理员权限' });

  removeOne(courses, 'id', req.params.id);
  operationLogs.push({ time: new Date().toISOString(), admin: session.name, action: '删除课程', target: req.params.id });
  res.json({ success: true, message: '删除成功' });
});

app.post('/api/admin/grades', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ success: false, message: '请先登录' });
  const token = authHeader.slice(7);
  const session = activeTokens.get(token);
  if (!session || session.role !== 'admin') return res.status(403).json({ success: false, message: '无管理员权限' });

  const { studentId, courseId } = req.body;
  const idx = grades.findIndex(g => g.studentId === studentId && g.courseId === courseId);
  if (idx >= 0) { Object.assign(grades[idx], req.body); }
  else { grades.push(req.body); }
  res.json({ success: true, message: '成绩保存成功' });
});

app.post('/api/admin/grades/batch', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ success: false, message: '请先登录' });
  const token = authHeader.slice(7);
  const session = activeTokens.get(token);
  if (!session || session.role !== 'admin') return res.status(403).json({ success: false, message: '无管理员权限' });

  const { grades: newGrades } = req.body;
  if (!Array.isArray(newGrades)) return res.json({ success: false, message: '数据格式错误' });
  let count = 0;
  newGrades.forEach(g => {
    const idx = grades.findIndex(x => x.studentId === g.studentId && x.courseId === g.courseId);
    if (idx >= 0) { Object.assign(grades[idx], g); } else { grades.push(g); count++; }
  });
  operationLogs.push({ time: new Date().toISOString(), admin: session.name, action: '批量导入成绩', target: `${newGrades.length}条` });
  res.json({ success: true, message: `成功处理${newGrades.length}条成绩` });
});

app.post('/api/admin/students/batch', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ success: false, message: '请先登录' });
  const token = authHeader.slice(7);
  const session = activeTokens.get(token);
  if (!session || session.role !== 'admin') return res.status(403).json({ success: false, message: '无管理员权限' });

  const { students: newStudents } = req.body;
  if (!Array.isArray(newStudents)) return res.json({ success: false, message: '数据格式错误' });
  newStudents.forEach(s => {
    if (!findOne(students, 'studentId', s.studentId)) {
      students.push(s);
      // 同时创建用户
      if (!findOne(users, 'username', s.studentId)) {
        users.push({
          username: s.studentId, password: bcrypt.hashSync('123456', 10), role: 'student',
          name: s.name, studentId: s.studentId, department: s.department || '',
          major: s.major || '', className: s.className || '', gender: s.gender || '男',
          enrollYear: s.enrollYear || '2024'
        });
      }
    }
  });
  operationLogs.push({ time: new Date().toISOString(), admin: session.name, action: '批量导入学生', target: `${newStudents.length}人` });
  res.json({ success: true, message: `成功导入${newStudents.length}名学生` });
});

app.post('/api/admin/notices', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ success: false, message: '请先登录' });
  const token = authHeader.slice(7);
  const session = activeTokens.get(token);
  if (!session || session.role !== 'admin') return res.status(403).json({ success: false, message: '无管理员权限' });

  notices.unshift({ ...req.body, important: req.body.important === true || req.body.important === 'true' });
  res.json({ success: true, message: '发布成功' });
});

app.delete('/api/admin/notices/:id', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ success: false, message: '请先登录' });
  const token = authHeader.slice(7);
  const session = activeTokens.get(token);
  if (!session || session.role !== 'admin') return res.status(403).json({ success: false, message: '无管理员权限' });

  removeOne(notices, 'id', req.params.id);
  res.json({ success: true, message: '删除成功' });
});

app.post('/api/admin/exams', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ success: false, message: '请先登录' });
  const token = authHeader.slice(7);
  const session = activeTokens.get(token);
  if (!session || session.role !== 'admin') return res.status(403).json({ success: false, message: '无管理员权限' });

  exams.push(req.body);
  res.json({ success: true, message: '添加成功' });
});

app.delete('/api/admin/exams/:id', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ success: false, message: '请先登录' });
  const token = authHeader.slice(7);
  const session = activeTokens.get(token);
  if (!session || session.role !== 'admin') return res.status(403).json({ success: false, message: '无管理员权限' });

  removeOne(exams, 'id', req.params.id);
  res.json({ success: true, message: '删除成功' });
});

// 学校配置更新
app.post('/api/admin/config', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ success: false, message: '请先登录' });
  const token = authHeader.slice(7);
  const session = activeTokens.get(token);
  if (!session || session.role !== 'admin') return res.status(403).json({ success: false, message: '无管理员权限' });

  Object.assign(schoolConfig, req.body);
  operationLogs.push({ time: new Date().toISOString(), admin: session.name, action: '修改学校配置', target: '' });
  res.json({ success: true, message: '配置已更新' });
});

// 操作日志
app.get('/api/admin/logs', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ success: false, message: '请先登录' });
  const token = authHeader.slice(7);
  const session = activeTokens.get(token);
  if (!session || session.role !== 'admin') return res.status(403).json({ success: false, message: '无管理员权限' });

  res.json({ success: true, data: operationLogs.slice(-100).reverse() });
});

// 统计数据
app.get('/api/admin/stats', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ success: false, message: '请先登录' });
  const token = authHeader.slice(7);
  const session = activeTokens.get(token);
  if (!session || session.role !== 'admin') return res.status(403).json({ success: false, message: '无管理员权限' });

  res.json({
    success: true,
    data: {
      totalStudents: students.filter(s => s.status === '在读').length,
      totalRegistered: users.filter(u => u.role === 'student').length,
      totalTeachers: users.filter(u => u.role === 'teacher').length,
      totalCourses: courses.length,
      totalGrades: grades.length,
      onlineCount: onlineUsers.size,
      onlineUsers: [...onlineUsers.values()].map(v => ({ name: v.name, role: v.role, lastActive: new Date(v.lastActive).toISOString() })),
      departments: [...new Set(students.map(s => s.department).filter(Boolean))],
      studentByDept: [...new Set(students.map(s => s.department).filter(Boolean))].map(d => ({
        department: d,
        count: students.filter(s => s.department === d).length
      }))
    }
  });
});

// ==================== 新增 API：邮箱绑定、找回密码、留言、在线统计、打赏 ====================

// 在线状态（公开）
app.get('/api/online', (req, res) => {
  res.json({ success: true, data: { count: onlineUsers.size, users: [...onlineUsers.values()].map(v => ({ name: v.name, role: v.role, lastActive: v.lastActive })) } });
});

// 注册用户统计（公开）
app.get('/api/user-stats', (req, res) => {
  res.json({ success: true, data: { totalStudents: users.filter(u => u.role === 'student').length, totalTeachers: users.filter(u => u.role === 'teacher').length, totalRegistered: users.length } });
});

// 发送邮箱验证码
app.post('/api/send-code', (req, res) => {
  const { email, username, type } = req.body; // type: 'bind' | 'reset'
  if (!email || !email.includes('@')) return res.json({ success: false, message: '请输入有效邮箱' });
  if (type === 'reset' && !username) return res.json({ success: false, message: '请输入账号' });

  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const expires = Date.now() + 600000; // 10分钟有效
  emailCodes.set(email, { code, expires, username, type });

  if (SMTP_CONFIG.auth.pass) {
    const subject = type === 'bind' ? 'H大学教务系统 - 邮箱绑定验证码' : 'H大学教务系统 - 密码找回验证码';
    const html = `<div style="max-width:500px;margin:0 auto;font-family:Arial,sans-serif;">
      <h2 style="color:#8B1A2B;">H大学 教务系统</h2>
      <p>您的验证码是：</p>
      <h1 style="font-size:40px;letter-spacing:8px;text-align:center;background:#f5f5f5;padding:20px;border-radius:8px;">${code}</h1>
      <p>验证码有效期10分钟，请勿泄露。</p>
      <p style="color:#999;">如果不是您本人的操作，请忽略此邮件。</p>
    </div>`;
    sendEmail(email, subject, html).then(ok => {
      if (ok) res.json({ success: true, message: '验证码已发送到邮箱' });
      else res.json({ success: true, message: `验证码: ${code} (邮件发送失败，请检查SMTP配置)` });
    });
  } else {
    // 无SMTP时返回验证码（开发模式）
    res.json({ success: true, message: `验证码: ${code} (未配置SMTP，请注意保管)`, code });
  }
});

// 验证验证码
app.post('/api/verify-code', (req, res) => {
  const { email, code } = req.body;
  const record = emailCodes.get(email);
  if (!record) return res.json({ success: false, message: '未发送验证码或已过期' });
  if (record.expires < Date.now()) { emailCodes.delete(email); return res.json({ success: false, message: '验证码已过期' }); }
  if (record.code !== code) return res.json({ success: false, message: '验证码错误' });
  if (record.type === 'bind') {
    emailCodes.delete(email);
    res.json({ success: true, verified: true });
  } else if (record.type === 'reset') {
    res.json({ success: true, verified: true });
  }
});

// 绑定邮箱
app.post('/api/bind-email', (req, res) => {
  const { username, email, code } = req.body;
  const record = emailCodes.get(email);
  if (!record || record.code !== code || record.expires < Date.now()) {
    return res.json({ success: false, message: '验证码无效或已过期' });
  }
  const user = findOne(users, 'username', sanitize(username));
  if (!user) return res.json({ success: false, message: '用户不存在' });
  user.email = email;
  emailCodes.delete(email);
  res.json({ success: true, message: '邮箱绑定成功！' });
});

// 通过邮箱重置密码
app.post('/api/reset-password', (req, res) => {
  const { username, email, code, newPassword } = req.body;
  const record = emailCodes.get(email);
  if (!record || record.code !== code || record.expires < Date.now()) {
    return res.json({ success: false, message: '验证码无效或已过期' });
  }
  if (record.username !== sanitize(username)) return res.json({ success: false, message: '账号与邮箱不匹配' });
  if (!newPassword || newPassword.length < 6) return res.json({ success: false, message: '新密码至少6位' });
  const user = findOne(users, 'username', sanitize(username));
  if (!user) return res.json({ success: false, message: '用户不存在' });
  user.password = bcrypt.hashSync(newPassword, 10);
  emailCodes.delete(email);
  res.json({ success: true, message: '密码重置成功！请用新密码登录' });
});

// ==================== 留言板 API ====================
// 获取留言
app.get('/api/messages', (req, res) => {
  res.json({ success: true, data: messages.slice(-50).reverse() });
});

// 发表留言
app.post('/api/messages', (req, res) => {
  const { content, userId, userName } = req.body;
  if (!content || !content.trim()) return res.json({ success: false, message: '留言内容不能为空' });
  if (content.length > 500) return res.json({ success: false, message: '留言最多500字' });
  messages.push({
    id: 'M' + Date.now(),
    userId: sanitize(userId) || 'anonymous',
    userName: sanitize(userName) || '匿名用户',
    content: sanitize(content),
    time: new Date().toISOString()
  });
  // 保留最近200条
  if (messages.length > 200) messages = messages.slice(-200);
  res.json({ success: true, message: '留言成功！' });
});

// 删除留言（管理员）
app.delete('/api/messages/:id', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ success: false, message: '请先登录' });
  const token = authHeader.slice(7);
  const session = activeTokens.get(token);
  if (!session || session.role !== 'admin') return res.status(403).json({ success: false, message: '无管理员权限' });
  messages = messages.filter(m => m.id !== req.params.id);
  res.json({ success: true, message: '删除成功' });
});

// ==================== 打赏 API ====================
// 获取打赏信息
app.get('/api/donate', (req, res) => {
  res.json({ success: true, data: donateInfo });
});

// 更新打赏信息（管理员）
app.post('/api/admin/donate', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ success: false, message: '请先登录' });
  const token = authHeader.slice(7);
  const session = activeTokens.get(token);
  if (!session || session.role !== 'admin') return res.status(403).json({ success: false, message: '无管理员权限' });
  Object.assign(donateInfo, req.body);
  res.json({ success: true, message: '打赏信息已更新' });
});

// ==================== 友情链接 API ====================
// 公开
app.get('/api/friend-links', (req, res) => {
  res.json({ success: true, data: friendLinks });
});
// 管理端
app.get('/api/admin/friend-links', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ success: false, message: '请先登录' });
  const token = authHeader.slice(7);
  const session = activeTokens.get(token);
  if (!session || session.role !== 'admin') return res.status(403).json({ success: false, message: '无管理员权限' });
  res.json({ success: true, data: friendLinks });
});
app.post('/api/admin/friend-links', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ success: false, message: '请先登录' });
  const token = authHeader.slice(7);
  const session = activeTokens.get(token);
  if (!session || session.role !== 'admin') return res.status(403).json({ success: false, message: '无管理员权限' });
  friendLinks = req.body.links || req.body;
  res.json({ success: true, message: '友情链接已更新' });
});

// ==================== 学校配置API（扩展） ====================
// 获取完整配置（公开）
app.get('/api/config', (req, res) => {
  res.json({ success: true, data: { ...schoolConfig, friendLinks, donateInfo } });
});
// 管理员更新配置
app.post('/api/admin/config', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ success: false, message: '请先登录' });
  const token = authHeader.slice(7);
  const session = activeTokens.get(token);
  if (!session || session.role !== 'admin') return res.status(403).json({ success: false, message: '无管理员权限' });
  Object.assign(schoolConfig, req.body);
  res.json({ success: true, message: '配置已更新' });
});

// 所有系部列表
app.get('/api/departments', (req, res) => {
  res.json({ success: true, data: [...new Set(students.map(s => s.department).filter(Boolean))] });
});

// 验证 token
app.get('/api/verify-token', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return res.json({ success: false });
  const token = authHeader.slice(7);
  const session = activeTokens.get(token);
  if (!session) return res.json({ success: false });
  res.json({ success: true, user: session });
});

// ==================== 静态文件服务 ====================
app.use(express.static(path.join(__dirname, '..')));
app.get(/^\/(?!api\/).*/, (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'index.html'));
});

module.exports = app;

if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  initData();
  app.listen(PORT, () => {
    console.log(`✅ H大学教务系统已启动: http://localhost:${PORT}`);
    console.log(`📋 管理员: admin / admin123`);
    console.log(`📋 教师: t001 / 123456`);
    console.log(`📋 学生: 20230101001 / 123456`);
  });
} else {
  initData();
}
