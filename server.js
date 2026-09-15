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
            let paramIndex = 1;
            const pgSql = sql.replace(/\?/g, () => `$${paramIndex++}`);
            
            db.query(pgSql, params)
                .then(res => resolve({ rows: res.rows, lastID: res.rows[0]?.id }))
                .catch(err => reject(err));
        } else {
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
    cookie: { maxAge: 24 * 60 * 60 * 1000 }
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
   USER ADMISSIONS & MANAGING USERS
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
        const { rows } = await queryDb(`SELECT id, system_id, full_name, email, role, detail, username, pin, created_at FROM users ORDER BY id DESC`);
        res.json({ users: rows });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// DELETE User Account (Admin Only)
app.delete('/api/users/:id', requireAdmin, async (req, res) => {
    try {
        await queryDb(`DELETE FROM users WHERE id = ?`, [req.params.id]);
        res.json({ success: true, message: 'User deleted successfully.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* ==========================================
   VIDEO & MEDIA UPLOAD MODULE
========================================== */

app.get('/api/videos', async (req, res) => {
    try {
        const { rows } = await queryDb(`SELECT * FROM videos ORDER BY id DESC`);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/videos', requireAdmin, upload.single('video_file'), async (req, res) => {
    const { title, category, description, video_url } = req.body;
    let fileUrl = video_url || '';

    if (req.file) {
        fileUrl = `/uploads/${req.file.filename}`;
    }

    if (!title || !category) {
        return res.status(400).json({ error: 'Title and category are required.' });
    }

    try {
        await queryDb(
            `INSERT INTO videos (title, category, description, file_url) VALUES (?, ?, ?, ?)`,
            [title, category, description, fileUrl]
        );
        res.json({ message: 'Video uploaded successfully.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// DELETE Uploaded Video or Media Link (Admin Only)
app.delete('/api/videos/:id', requireAdmin, async (req, res) => {
    try {
        const video = await getDbRow(`SELECT * FROM videos WHERE id = ?`, [req.params.id]);
        if (!video) return res.status(404).json({ error: 'Video record not found.' });

        // Remove actual video file if stored on server
        if (video.file_url && video.file_url.startsWith('/uploads/')) {
            const filePath = path.join(__dirname, video.file_url);
            if (fs.existsSync(filePath)) {
                fs.unlinkSync(filePath);
            }
        }

        await queryDb(`DELETE FROM videos WHERE id = ?`, [req.params.id]);
        res.json({ success: true, message: 'Video post deleted successfully.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* ==========================================
   TEACHER WORKFLOW & QUESTION APPROVAL MODULE
========================================== */

app.post('/api/questions/upload', requireTeacher, async (req, res) => {
    const { teacher_name, subject, class_level, question_text, option_a, option_b, option_c, option_d, correct_option } = req.body;
    
    if (!teacher_name || !subject || !class_level || !question_text || !correct_option) {
        return res.status(400).json({ error: 'All question details are required.' });
    }

    try {
        await queryDb(
            `INSERT INTO questions (teacher_name, subject, class_level, question_text, option_a, option_b, option_c, option_d, correct_option, status) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')`,
            [teacher_name, subject, class_level, question_text, option_a, option_b, option_c, option_d, correct_option]
        );
        res.json({ success: true, message: 'Question submitted for Admin approval.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/admin/pending-questions', requireAdmin, async (req, res) => {
    try {
        const { rows } = await queryDb(`SELECT * FROM questions WHERE status = 'pending' ORDER BY id DESC`);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/admin/approve-question', requireAdmin, async (req, res) => {
    const { question_id, action } = req.body;
    if (!question_id || !action) {
        return res.status(400).json({ error: 'Question ID and action are required.' });
    }

    try {
        await queryDb(`UPDATE questions SET status = ? WHERE id = ?`, [action, question_id]);
        res.json({ success: true, message: `Question ${action} successfully.` });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// DELETE Question (Admin or Teacher)
app.delete('/api/questions/:id', requireTeacher, async (req, res) => {
    try {
        await queryDb(`DELETE FROM questions WHERE id = ?`, [req.params.id]);
        res.json({ success: true, message: 'Question deleted successfully.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* ==========================================
   CBT EXAM & STUDENT RESULT MODULES
========================================== */

app.get('/api/questions', async (req, res) => {
    const { subject, class_level } = req.query;

    let sql = `
        SELECT id, question_text, option_a, option_b, option_c, option_d, correct_option 
        FROM questions 
        WHERE status = 'approved'
    `;
    const params = [];

    if (subject && class_level) {
        sql += ` AND LOWER(TRIM(subject)) = LOWER(TRIM(?)) AND LOWER(TRIM(class_level)) = LOWER(TRIM(?))`;
        params.push(subject, class_level);
    } else if (subject) {
        sql += ` AND LOWER(TRIM(subject)) = LOWER(TRIM(?))`;
        params.push(subject);
    }

    try {
        const { rows } = await queryDb(sql, params);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/exams/create', requireTeacher, async (req, res) => {
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
                `INSERT INTO questions (exam_id, question_text, option_a, option_b, option_c, option_d, correct_option, status) VALUES (?, ?, ?, ?, ?, ?, ?, 'approved')`,
                [examId, text, a, b, c, d, correct]
            );
        }

        res.json({ message: 'Exam Published Successfully', examId });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// DELETE Exam and associated Questions (Teacher/Admin Only)
app.delete('/api/exams/:id', requireTeacher, async (req, res) => {
    try {
        await queryDb(`DELETE FROM questions WHERE exam_id = ?`, [req.params.id]);
        await queryDb(`DELETE FROM exams WHERE id = ?`, [req.params.id]);
        res.json({ success: true, message: 'Exam and linked questions deleted.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/exams/submit', async (req, res) => {
    const { studentId, studentName, classLevel, subject, term, answers } = req.body;

    try {
        const { rows: questions } = await queryDb(`SELECT id, correct_option FROM questions WHERE LOWER(TRIM(subject)) = LOWER(TRIM(?)) AND status = 'approved'`, [subject]);

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

        if (term) {
            await queryDb(
                `INSERT INTO student_results (student_id, student_name, class_level, subject, score, total_questions, term) VALUES (?, ?, ?, ?, ?, ?, ?)`,
                [studentId, studentName, classLevel, subject, score, total, term]
            );
        }

        res.json({ score, total, percentage });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/results/check', async (req, res) => {
    const { student_id, term } = req.query;

    if (!student_id || !term) {
        return res.status(400).json({ error: 'Student ID and Term are required.' });
    }

    try {
        const { rows } = await queryDb(
            `SELECT * FROM student_results WHERE LOWER(TRIM(student_id)) = LOWER(TRIM(?)) AND LOWER(TRIM(term)) = LOWER(TRIM(?)) ORDER BY created_at DESC`,
            [student_id, term]
        );
        res.json(rows);
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

app.get('/api/news', async (req, res) => {
    try {
        const { rows } = await queryDb(`SELECT * FROM news ORDER BY created_at DESC`);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

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

// DELETE News Article (Teacher/Admin Only)
app.delete('/api/news/:id', requireTeacher, async (req, res) => {
    try {
        await queryDb(`DELETE FROM news WHERE id = ?`, [req.params.id]);
        res.json({ success: true, message: 'News post deleted successfully.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/resources', async (req, res) => {
    try {
        const { rows } = await queryDb(`SELECT * FROM resources ORDER BY uploaded_at DESC`);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

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

// DELETE Download Resource File (Teacher/Admin Only)
app.delete('/api/resources/:id', requireTeacher, async (req, res) => {
    try {
        const resource = await getDbRow(`SELECT * FROM resources WHERE id = ?`, [req.params.id]);
        if (!resource) return res.status(404).json({ error: 'Resource file not found.' });

        // Unlink physical document from /uploads folder
        if (resource.file_url && resource.file_url.startsWith('/uploads/')) {
            const filePath = path.join(__dirname, resource.file_url);
            if (fs.existsSync(filePath)) {
                fs.unlinkSync(filePath);
            }
        }

        await queryDb(`DELETE FROM resources WHERE id = ?`, [req.params.id]);
        res.json({ success: true, message: 'Resource document deleted successfully.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

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