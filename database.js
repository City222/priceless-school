const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcryptjs');

const dbPath = path.resolve(__dirname, 'priceless_school.db');
const db = new sqlite3.Database(dbPath);

db.serialize(() => {
    // Users Table (Admins, Teachers, Students)
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            system_id TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            role TEXT CHECK(role IN ('Admin', 'Teacher', 'Student')) NOT NULL,
            detail TEXT, -- Subject for Teachers, Class for Students
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            pin TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // Exams Metadata Table
    db.run(`
        CREATE TABLE IF NOT EXISTS exams (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subject TEXT NOT NULL,
            class_level TEXT NOT NULL,
            term INTEGER NOT NULL,
            file_path TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // CBT Questions Table
    db.run(`
        CREATE TABLE IF NOT EXISTS questions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            exam_id INTEGER NOT NULL,
            question_text TEXT NOT NULL,
            option_a TEXT NOT NULL,
            option_b TEXT NOT NULL,
            option_c TEXT NOT NULL,
            option_d TEXT NOT NULL,
            correct_option TEXT NOT NULL,
            FOREIGN KEY (exam_id) REFERENCES exams(id) ON DELETE CASCADE
        )
    `);

    // Exam Results Table
    db.run(`
        CREATE TABLE IF NOT EXISTS exam_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id TEXT NOT NULL,
            student_name TEXT NOT NULL,
            class_level TEXT NOT NULL,
            subject TEXT NOT NULL,
            score INTEGER NOT NULL,
            total_questions INTEGER NOT NULL,
            percentage REAL NOT NULL,
            date_taken DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // Events & Gallery Table
    db.run(`
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            gallery_target TEXT CHECK(gallery_target IN ('student', 'activities')) NOT NULL,
            title TEXT NOT NULL,
            event_date TEXT,
            description TEXT NOT NULL,
            image_url TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // Bootstrap Super Admin Account
    const adminPasswordHash = bcrypt.hashSync('AdminPass2026!', 10);
    db.run(`
        INSERT OR IGNORE INTO users (system_id, full_name, email, role, detail, username, password_hash)
        VALUES ('ADMIN-001', 'System Administrator', 'admin@pricelessschool.com', 'Admin', 'Super User', 'PCI-ADMIN', ?)
    `, [adminPasswordHash]);
});

module.exports = db;