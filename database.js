const path = require('path');
const bcrypt = require('bcryptjs');

// Determine environment: Use PostgreSQL on Render/Production, SQLite for Local Testing
const isProduction = process.env.DATABASE_URL || process.env.NODE_ENV === 'production';

let db;

if (isProduction) {
    // --- POSTGRESQL CONFIGURATION (Render / Production) ---
    const { Pool } = require('pg');
    const pool = new Pool({
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false }
    });

    const initPgDb = async () => {
        try {
            await pool.query(`
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    system_id VARCHAR(100) UNIQUE NOT NULL,
                    full_name VARCHAR(255) NOT NULL,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    role VARCHAR(50) CHECK(role IN ('Admin', 'Teacher', 'Student')) NOT NULL,
                    detail VARCHAR(255),
                    username VARCHAR(100) UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    pin VARCHAR(50),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS exams (
                    id SERIAL PRIMARY KEY,
                    subject VARCHAR(100) NOT NULL,
                    class_level VARCHAR(50) NOT NULL,
                    term INT NOT NULL,
                    file_path TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS questions (
                    id SERIAL PRIMARY KEY,
                    exam_id INT REFERENCES exams(id) ON DELETE CASCADE,
                    question_text TEXT NOT NULL,
                    option_a TEXT NOT NULL,
                    option_b TEXT NOT NULL,
                    option_c TEXT NOT NULL,
                    option_d TEXT NOT NULL,
                    correct_option VARCHAR(10) NOT NULL
                );

                CREATE TABLE IF NOT EXISTS exam_results (
                    id SERIAL PRIMARY KEY,
                    student_id VARCHAR(100) NOT NULL,
                    student_name VARCHAR(255) NOT NULL,
                    class_level VARCHAR(50) NOT NULL,
                    subject VARCHAR(100) NOT NULL,
                    score INT NOT NULL,
                    total_questions INT NOT NULL,
                    percentage REAL NOT NULL,
                    date_taken TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS events (
                    id SERIAL PRIMARY KEY,
                    gallery_target VARCHAR(50) CHECK(gallery_target IN ('student', 'activities')) NOT NULL,
                    title VARCHAR(255) NOT NULL,
                    event_date VARCHAR(100),
                    description TEXT NOT NULL,
                    image_url TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS news (
                    id SERIAL PRIMARY KEY,
                    title VARCHAR(255) NOT NULL,
                    category VARCHAR(100) NOT NULL,
                    body TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS resources (
                    id SERIAL PRIMARY KEY,
                    title VARCHAR(255) NOT NULL,
                    target_class VARCHAR(50) NOT NULL,
                    file_url TEXT NOT NULL,
                    file_name VARCHAR(255) NOT NULL,
                    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            `);

            // Seed Super Admin if not existing
            const adminPasswordHash = bcrypt.hashSync('AdminPass2026!', 10);
            await pool.query(`
                INSERT INTO users (system_id, full_name, email, role, detail, username, password_hash)
                VALUES ('ADMIN-001', 'System Administrator', 'admin@pricelessschool.com', 'Admin', 'Super User', 'PCI-ADMIN', $1)
                ON CONFLICT (system_id) DO NOTHING;
            `, [adminPasswordHash]);

            console.log("PostgreSQL Database initialized successfully.");
        } catch (err) {
            console.error("Error initializing PostgreSQL database:", err);
        }
    };

    initPgDb();
    db = pool;

} else {
    // --- SQLITE CONFIGURATION (Local Development) ---
    const sqlite3 = require('sqlite3').verbose();
    const dbPath = path.resolve(__dirname, 'priceless_school.db');
    db = new sqlite3.Database(dbPath);

    db.serialize(() => {
        db.run(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                system_id TEXT UNIQUE NOT NULL,
                full_name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                role TEXT CHECK(role IN ('Admin', 'Teacher', 'Student')) NOT NULL,
                detail TEXT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                pin TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `);

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

        // New Parents & News Tables
        db.run(`
            CREATE TABLE IF NOT EXISTS news (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                category TEXT NOT NULL,
                body TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `);

        db.run(`
            CREATE TABLE IF NOT EXISTS resources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                target_class TEXT NOT NULL,
                file_url TEXT NOT NULL,
                file_name TEXT NOT NULL,
                uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `);

        const adminPasswordHash = bcrypt.hashSync('AdminPass2026!', 10);
        db.run(`
            INSERT OR IGNORE INTO users (system_id, full_name, email, role, detail, username, password_hash)
            VALUES ('ADMIN-001', 'System Administrator', 'admin@pricelessschool.com', 'Admin', 'Super User', 'PCI-ADMIN', ?)
        `, [adminPasswordHash]);

        console.log("SQLite Database initialized successfully.");
    });
}

module.exports = db;