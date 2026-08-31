require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const db = require('./database');

const app = express();
const PORT = process.env.PORT || 5000;

// Ensure uploads folder exists
if (!fs.existsSync('uploads')) {
    fs.mkdirSync('uploads');
}

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(__dirname));

// Storage Setup
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'),
    filename: (req, file, cb) => cb(null, Date.now() + '-' + path.extname(file.originalname))
});
const upload = multer({ storage });

// Email Transporter Setup
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

app.post('/api/users/student', (req, res) => {
    const { name, studentClass, email } = req.body;
    if (!name || !studentClass || !email) {
        return res.status(400).json({ error: 'Name, class level, and email are required.' });
    }

    db.get(`SELECT COUNT(*) AS count FROM users WHERE role = 'Student'`, [], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });

        const count = String(row.count + 1).padStart(3, '0');
        const admissionNo = `PCI/${new Date().getFullYear()}/${count}`;
        const pin = Math.floor(1000 + Math.random() * 9000).toString();
        const hash = bcrypt.hashSync(pin, 10);

        db.run(
            `INSERT INTO users (system_id, full_name, email, role, detail, username, password_hash, pin) VALUES (?, ?, ?, 'Student', ?, ?, ?, ?)`,
            [admissionNo, name, email, studentClass, admissionNo, hash, pin],
            function (dbErr) {
                if (dbErr) return res.status(500).json({ error: dbErr.message });

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
            }
        );
    });
});

app.get('/api/users', (req, res) => {
    db.all(`SELECT system_id, full_name, email, role, detail, username, pin, created_at FROM users ORDER BY id DESC`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ users: rows });
    });
});

/* ==========================================
   CBT EXAM MODULE
========================================== */

app.post('/api/exams/create', (req, res) => {
    const { subject, classLevel, term, questions } = req.body;

    db.run(`INSERT INTO exams (subject, class_level, term) VALUES (?, ?, ?)`, [subject, classLevel, term], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        const examId = this.lastID;

        const stmt = db.prepare(`INSERT INTO questions (exam_id, question_text, option_a, option_b, option_c, option_d, correct_option) VALUES (?, ?, ?, ?, ?, ?, ?)`);
        questions.forEach(q => stmt.run(examId, q.text, q.a, q.b, q.c, q.d, q.correct));
        stmt.finalize();

        res.json({ message: 'Exam Published', examId });
    });
});

app.post('/api/exams/submit', (req, res) => {
    const { studentId, studentName, classLevel, subject, examId, answers } = req.body;

    db.all(`SELECT id, correct_option FROM questions WHERE exam_id = ?`, [examId], (err, questions) => {
        if (err) return res.status(500).json({ error: err.message });

        let score = 0;
        questions.forEach(q => {
            if (answers[q.id] && answers[q.id].toUpperCase() === q.correct_option.toUpperCase()) {
                score++;
            }
        });

        const total = questions.length;
        const percentage = total > 0 ? ((score / total) * 100).toFixed(2) : 0;

        db.run(
            `INSERT INTO exam_results (student_id, student_name, class_level, subject, score, total_questions, percentage) VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [studentId, studentName, classLevel, subject, score, total, percentage],
            (resErr) => {
                if (resErr) return res.status(500).json({ error: resErr.message });
                res.json({ score, total, percentage });
            }
        );
    });
});

/* ==========================================
   PARENT RESULT PORTAL
========================================== */

app.post('/api/parent/results', (req, res) => {
    const { admissionNo, pin } = req.body;

    db.get(`SELECT * FROM users WHERE username = ? AND role = 'Student'`, [admissionNo], (err, user) => {
        if (err || !user) return res.status(404).json({ error: 'Student record not found.' });

        if (user.pin !== pin && !bcrypt.compareSync(pin, user.password_hash)) {
            return res.status(401).json({ error: 'Invalid Portal PIN.' });
        }

        db.all(`SELECT * FROM exam_results WHERE student_id = ? ORDER BY date_taken DESC`, [admissionNo], (rErr, results) => {
            if (rErr) return res.status(500).json({ error: rErr.message });
            res.json({ studentName: user.full_name, classLevel: user.detail, results });
        });
    });
});

// Start Engine
app.listen(PORT, () => console.log(`School Backend active on http://localhost:${PORT}`));