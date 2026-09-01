require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const session = require('express-session');
const db = require('./database');

const app = express();

// Ensure uploads folder exists
if (!fs.existsSync('uploads')) {
    fs.mkdirSync('uploads');
}

// Check if running on PostgreSQL pool or SQLite db instance
const isPg = typeof db.query === 'function';

// Helper query function to bridge SQLite and PostgreSQL APIs
const queryDb = (sql, params = []) => {
    return new Promise((resolve, reject) => {
        if (isPg) {
            // Convert SQLite '?' parameters to PostgreSQL '$1, $2, ...'
            let paramIndex = 1;
            const pgSql = sql.replace(/\?/g, () => `$${paramIndex++}`);
            
            db.query(pgSql, params)
                .then(res => resolve({ rows: res.rows, lastID: res.rows[0]?.id }))
                .catch(err => reject(err));
        } else {
            // Check query intent (SELECT vs INSERT/UPDATE)
            const isSelect = sql.trim().toUpperCase().startsWith('SELECT');
            if (isSelect) {
                db.all(sql, params, (err, rows) => {
                    if (err) reject(err);
                    else resolve({ rows });
                });
            } else {
                db.run(sql, params, function (err) {
                    if (err) reject(err);
                    else resolve({ lastID: this.lastID });
                });
            }
        }
    });
};

// Helper for single row queries
const getDbRow = (sql, params = []) => {
    return new Promise((resolve, reject) => {
        if (isPg) {
            let paramIndex = 1;
            const pgSql = sql.replace(/\?/g, () => `$${paramIndex++}`);
            db.query(pgSql, params)
                .then(res => resolve(res.rows[0] || null))
                .catch(err => reject(err));
        } else {
            db.get(sql, params, (err, row) => {
                if (err) reject(err);
                else resolve(row || null);
            });
        }
    });
};

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// 1. SESSION CONFIGURATION
app.use(session({
    secret: process.env.SESSION_SECRET || 'priceless_school_secret_key',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 } // Session expires in 24 hours
}));

// 2. SECURITY BOUNCER MIDDLEWARE
function requireAdmin(req, res, next) {
    if (req.session && req.session.user && req.session.user.role === 'Admin') {
        return next();
    }
    return res.status(403).send("Access Denied: You must be an Admin to access this page.");
}

function requireTeacher(req, res, next) {
    if (req.session && req.session.user && (req.session.user.role === 'Teacher' || req.session.user.role === 'Admin')) {
        return next();
    }
    return res.status(403).send("Access Denied: Teachers or Admins only.");
}

// 3. SECURED PAGE ROUTES
app.get('/Priceless1.html', requireAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'Priceless1.html'));
});

// Serve public static files EXCEPT protected ones
app.use(express.static(__dirname));

// Redirect root URL to Login page

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'Priceless1.html'));
});

/* ==========================================
   AUTHENTICATION & ROLE LOGIN
========================================== */

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Username and password are required.' });
    }

    try {
        const user = await getDbRow(`SELECT * FROM users WHERE username = ?`, [username]);
        if (!user) {
            return res.status(401).json({ success: false, message: 'Invalid credentials.' });
        }

        const isValidPin = user.pin && user.pin === password;
        const isValidHash = user.password_hash && bcrypt.compareSync(password, user.password_hash);

        if (!isValidPin && !isValidHash) {
            return res.status(401).json({ success: false, message: 'Invalid credentials.' });
        }

        req.session.user = {
            id: user.id,
            username: user.username,
            role: user.role
        };

        res.json({ success: true, role: user.role });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.post('/api/logout', (req, res) => {
    req.session.destroy(() => {
        res.json({ success: true, message: 'Logged out successfully.' });
    });
});

/* ==========================================
   STORAGE & EMAIL TRANSPORTER SETUP
========================================== */

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'),
    filename: (req, file, cb) => cb(null, Date.now() + '-' + path.extname(file.originalname))
});
const upload = multer({ storage });

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.SYSTEM_EMAIL,
        pass: process.env.EMAIL_PASS
    }
});

/* ==========================================
   USER ADMISSIONS & OWNER NOTIFICATIONS
========================================== */

app.post('/api/users/student', async (req, res) => {
    const { name, studentClass, email } = req.body;
    if (!name || !studentClass || !email) {
        return res.status(400).json({ error: 'Name, class level, and email are required.' });
    }

    try {
        const row = await getDbRow(`SELECT COUNT(*) AS count FROM users WHERE role = 'Student'`);
        const count = String(parseInt(row.count) + 1).padStart(3, '0');
        const admissionNo = `PCI/${new Date().getFullYear()}/${count}`;
        const pin = Math.floor(1000 + Math.random() * 9000).toString();
        const hash = bcrypt.hashSync(pin, 10);

        await queryDb(
            `INSERT INTO users (system_id, full_name, email, role, detail, username, password_hash, pin) VALUES (?, ?, ?, 'Student', ?, ?, ?, ?)`,
            [admissionNo, name, email, studentClass, admissionNo, hash, pin]
        );

        const mailOptions = {
            from: `"Priceless School Portal" <${process.env.SYSTEM_EMAIL}>`,
            to: process.env.OWNER_EMAIL,
            subject: '🔔 New Student Admission Registered',
            html: `
                <h2>New Student Registration Alert</h2>
                <p><strong>Full Name:</strong> ${name}</p>
                <p><strong>Class Applied:</strong> ${studentClass}</p>
                <p><strong>Student/Parent Email:</strong> ${email}</p>
                <p><strong>Admission No:</strong> <code>${admissionNo}</code></p>
                <p><strong>Portal PIN:</strong> <code>${pin}</code></p>
            `
        };

        transporter.sendMail(mailOptions, (mailErr) => {
            if (mailErr) console.error('Owner email alert failed:', mailErr);
        });

        res.json({ message: 'Student Admitted', admissionNo, pin, email });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/users', async (req, res) => {
    try {
        const { rows } = await queryDb(`SELECT system_id, full_name, email, role, detail, username, pin, created_at FROM users ORDER BY id DESC`);
        res.json({ users: rows });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* ==========================================
   CBT EXAM MODULE
========================================== */

app.get('/api/questions', async (req, res) => {
    const { subject, class_level } = req.query;

    let sql = `
        SELECT q.id, q.question_text, q.option_a, q.option_b, q.option_c, q.option_d, q.correct_option 
        FROM questions q
        JOIN exams e ON q.exam_id = e.id
    `;
    const params = [];

    if (subject && class_level) {
        sql += ` WHERE LOWER(TRIM(e.subject)) = LOWER(TRIM(?)) AND LOWER(TRIM(e.class_level)) = LOWER(TRIM(?))`;
        params.push(subject, class_level);
    } else if (subject) {
        sql += ` WHERE LOWER(TRIM(e.subject)) = LOWER(TRIM(?))`;
        params.push(subject);
    }

    try {
        const { rows } = await queryDb(sql, params);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/exams/create', async (req, res) => {
    const subject = req.body.subject;
    const classLevel = req.body.classLevel || req.body.class_level;
    const term = req.body.term || 1;
    const questions = req.body.questions || [];

    if (!subject || !classLevel) {
        return res.status(400).json({ error: 'Subject and Class Level are required.' });
    }

    try {
        const insertExamSql = isPg 
            ? `INSERT INTO exams (subject, class_level, term) VALUES (?, ?, ?) RETURNING id`
            : `INSERT INTO exams (subject, class_level, term) VALUES (?, ?, ?)`;
        
        const result = await queryDb(insertExamSql, [subject, classLevel, term]);
        const examId = result.lastID;

        for (const q of questions) {
            const text = q.text || q.question_text;
            const a = q.a || q.option_a;
            const b = q.b || q.option_b;
            const c = q.c || q.option_c;
            const d = q.d || q.option_d;
            const correct = q.correct || q.correct_option;

            await queryDb(
                `INSERT INTO questions (exam_id, question_text, option_a, option_b, option_c, option_d, correct_option) VALUES (?, ?, ?, ?, ?, ?, ?)`,
                [examId, text, a, b, c, d, correct]
            );
        }

        res.json({ message: 'Exam Published Successfully', examId });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/exams/submit', async (req, res) => {
    const { studentId, studentName, classLevel, subject, examId, answers } = req.body;

    try {
        const { rows: questions } = await queryDb(`SELECT id, correct_option FROM questions WHERE exam_id = ?`, [examId]);

        let score = 0;
        questions.forEach(q => {
            if (answers[q.id] && answers[q.id].toUpperCase() === q.correct_option.toUpperCase()) {
                score++;
            }
        });

        const total = questions.length;
        const percentage = total > 0 ? ((score / total) * 100).toFixed(2) : 0;

        await queryDb(
            `INSERT INTO exam_results (student_id, student_name, class_level, subject, score, total_questions, percentage) VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [studentId, studentName, classLevel, subject, score, total, percentage]
        );

        res.json({ score, total, percentage });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* ==========================================
   PARENT PORTAL, NEWS & RESOURCE MODULES
========================================== */

app.post('/api/parent/results', async (req, res) => {
    const { admissionNo, pin } = req.body;

    try {
        const user = await getDbRow(`SELECT * FROM users WHERE username = ? AND role = 'Student'`, [admissionNo]);
        if (!user) return res.status(404).json({ error: 'Student record not found.' });

        if (user.pin !== pin && !bcrypt.compareSync(pin, user.password_hash)) {
            return res.status(401).json({ error: 'Invalid Portal PIN.' });
        }

        const { rows: results } = await queryDb(`SELECT * FROM exam_results WHERE student_id = ? ORDER BY date_taken DESC`, [admissionNo]);
        res.json({ studentName: user.full_name, classLevel: user.detail, results });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// GET all published news
app.get('/api/news', async (req, res) => {
    try {
        const { rows } = await queryDb(`SELECT * FROM news ORDER BY created_at DESC`);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// POST new bulletin announcement
app.post('/api/news', requireTeacher, async (req, res) => {
    const { title, category, body } = req.body;
    if (!title || !category || !body) {
        return res.status(400).json({ error: 'Title, category, and content body are required.' });
    }

    try {
        await queryDb(`INSERT INTO news (title, category, body) VALUES (?, ?, ?)`, [title, category, body]);
        res.json({ message: 'News bulletin posted successfully.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// GET list of parent downloads/resources
app.get('/api/resources', async (req, res) => {
    try {
        const { rows } = await queryDb(`SELECT * FROM resources ORDER BY uploaded_at DESC`);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// POST upload new parent resource (PDF/Document)
app.post('/api/resources', requireTeacher, upload.single('file'), async (req, res) => {
    const { title, target_class } = req.body;
    if (!req.file || !title || !target_class) {
        return res.status(400).json({ error: 'File, title, and target class are required.' });
    }

    const file_url = `/uploads/${req.file.filename}`;
    const file_name = req.file.originalname;

    try {
        await queryDb(
            `INSERT INTO resources (title, target_class, file_url, file_name) VALUES (?, ?, ?, ?)`,
            [title, target_class, file_url, file_name]
        );
        res.json({ message: 'Resource uploaded successfully.', file_url });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Debug Endpoint to view existing database exams
app.get('/api/debug/exams', async (req, res) => {
    try {
        const { rows } = await queryDb(`SELECT * FROM exams`);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Start Engine on Port 5000
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`School Backend active on http://localhost:${PORT}`));