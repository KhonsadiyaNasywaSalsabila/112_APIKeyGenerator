const express = require('express');
const path = require('path');
const crypto = require('crypto');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs'); 
const session = require('express-session');
const app = express();
const port = 3000;

// --- Konfigurasi Database ---
const dbConfig = {
    host: '127.0.0.1',
    port: 3309,
    user: 'root', 
    password: '905.Nasywa', // PASTIKAN PASSWORD INI SUDAH BENAR!
    database: 'apikey',
};

const pool = mysql.createPool(dbConfig);

// Pengecekan Koneksi Database
async function checkDbConnection() {
    try {
        const connection = await pool.getConnection();
        console.log('✅ Koneksi ke database MySQL berhasil.');
        connection.release();
    } catch (error) {
        console.error('❌ Gagal terhubung ke database MySQL:', error.message);
        process.exit(1);
    }
}
checkDbConnection();

// --- Konfigurasi Middleware ---

app.use(express.json()); 
app.use(express.urlencoded({ extended: true }));

// Konfigurasi Session
app.use(session({
    secret: 'ini-adalah-secret-super-kuat-untuk-session-anda-912347', 
    resave: false,
    saveUninitialized: false,
    // Gunakan httpOnly: true untuk keamanan cookie
    cookie: { maxAge: 1000 * 60 * 60 * 24, httpOnly: true }
}));

// Middleware untuk menyajikan file statis dari folder 'public'
app.use(express.static(path.join(__dirname, 'public')));


// Middleware Pelindung Rute Admin
function requireAdmin(req, res, next) {
    // Memperbaiki pengecekan role yang tidak konsisten dengan skema Login Admin yang baru
    if (req.session.user && req.session.user.role === 'admin') {
        next(); 
    } else {
        res.redirect('/login');
    }
}

// =================================================================
// ⬇️ 1. ENDPOINT ROOT & API KEY VALIDATION (CORE FUNCTIONALITY)
// =================================================================

// MEMPERBAIKI ERROR ENOENT: Mengarahkan halaman root ke registrasi User
app.get('/', (req, res) => {
    // Langsung redirect ke endpoint user-register
    res.redirect('/user-register'); 
});

// Handler POST /checkapi - VALIDASI API KEY
app.post('/checkapi', async (req, res) => {
    const clientKey = req.body.key;
    if (!clientKey) {
        return res.status(400).json({ success: false, message: 'API Key diperlukan.' });
    }

    try {
        // Query untuk mencari key yang AKTIF
        const sqlSelect = "SELECT * FROM api_keys WHERE api_key = ? AND is_active = TRUE";
        const [rows] = await pool.execute(sqlSelect, [clientKey]);

        if (rows.length > 0) {
            // Update last_used_at
            const sqlUpdate = "UPDATE api_keys SET last_used_at = CURRENT_TIMESTAMP WHERE api_key = ?";
            await pool.execute(sqlUpdate, [clientKey]);
            
            res.json({ success: true, message: 'API Key valid.' });
        } else {
            res.status(401).json({ success: false, message: 'API Key tidak valid atau dinonaktifkan.' });
        }

    } catch (error) {
        console.error('Error saat memvalidasi API key:', error.message);
        res.status(500).json({ success: false, message: 'Gagal memvalidasi API key di server.' });
    }
});


// =================================================================
// ⬇️ 2. ENDPOINT ADMIN (CRUD Logic)
// =================================================================

// RENDER LOGIN & REGISTER
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'public', 'register.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/dashboard', requireAdmin, (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));


// POST Registrasi Admin
app.post('/register', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).send('Email dan Password wajib diisi.');

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        // Memastikan nama kolom password di tabel admins sudah benar (diasumsikan 'password')
        const sql = "INSERT INTO admins (email, password) VALUES (?, ?)"; 
        await pool.execute(sql, [email, hashedPassword]);

        res.send('Registrasi Admin Berhasil. Silakan <a href="/login">Login</a>.');
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') return res.status(409).send('Email sudah terdaftar.');
        console.error('Error saat registrasi Admin:', error.message);
        res.status(500).send('Gagal melakukan registrasi.');
    }
});

// POST Login Admin
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // Memastikan nama kolom password di tabel admins sudah benar (diasumsikan 'password')
        const sql = "SELECT id, password, email FROM admins WHERE email = ?"; 
        const [rows] = await pool.execute(sql, [email]);
        
        if (rows.length === 0) return res.status(401).send('Email atau Password salah.');

        const admin = rows[0];
        const isMatch = await bcrypt.compare(password, admin.password);

        if (isMatch) {
            // Menyimpan sesi dengan role 'admin'
            req.session.user = { id: admin.id, email: admin.email, role: 'admin' }; 
            res.send(`Login successful. Redirecting... <script>window.location.href='/dashboard';</script>`);
        } else {
            res.status(401).send('Email atau Password salah.');
        }
    } catch (error) {
        console.error('Error saat login Admin:', error.message);
        res.status(500).send('Gagal melakukan login.');
    }
});

// GET Logout
app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) console.error('Error saat logout:', err);
        res.redirect('/login');
    });
});

// GET Data Dashboard (JSON)
app.get('/api/users', requireAdmin, async (req, res) => {
    try {
        const sql = `
            SELECT 
                u.id AS user_id, 
                u.first_name, 
                u.last_name, 
                u.email, 
                a.api_key,
                a.is_active,
                a.created_at,
                a.last_used_at
            FROM users u
            JOIN api_keys a ON u.id = a.user_id
            ORDER BY u.id ASC;
        `;
        const [users] = await pool.execute(sql);
        res.json(users);

    } catch (error) {
        console.error('Error saat mengambil data dashboard:', error.message);
        res.status(500).json({ message: 'Gagal memuat data dashboard.' });
    }
});

// DELETE Endpoint untuk menghapus User (BARU!)
app.delete('/api/users/delete/:id', requireAdmin, async (req, res) => {
    const userId = req.params.id;
    
    try {
        // Karena api_keys terhubung ke users dengan ON DELETE CASCADE,
        // menghapus user akan otomatis menghapus API key terkait.
        const sql = "DELETE FROM users WHERE id = ?";
        const [result] = await pool.execute(sql, [userId]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ success: false, message: 'User tidak ditemukan.' });
        }

        res.json({ success: true, message: `User ID ${userId} berhasil dihapus.` });

    } catch (error) {
        console.error('Error saat menghapus user:', error.message);
        res.status(500).json({ success: false, message: 'Gagal menghapus user di server.' });
    }
});


// =================================================================
// ⬇️ 3. ENDPOINT USER REGISTRATION (Creation Logic)
// =================================================================

// RENDER USER REGISTER
app.get('/user-register', (req, res) => {
    // Karena halaman user-register tidak memerlukan login Admin, kita kirimkan langsung
    res.sendFile(path.join(__dirname, 'public', 'user-register.html'));
});

// POST Pendaftaran User dan Generate API Key
app.post('/user-register', async (req, res) => {
    const { first_name, last_name, email } = req.body;

    if (!first_name || !last_name || !email) {
        return res.status(400).json({ success: false, message: 'Semua kolom wajib diisi.' });
    }

    const connection = await pool.getConnection(); 
    try {
        await connection.beginTransaction();

        // 1. Simpan User Baru ke tabel users
        const userSql = "INSERT INTO users (first_name, last_name, email) VALUES (?, ?, ?)";
        const [userResult] = await connection.execute(userSql, [first_name, last_name, email]);
        const newUserId = userResult.insertId;

        // 2. Generate dan Simpan API Key (One-to-One)
        const randomBytes = crypto.randomBytes(32);
        const keyHex = randomBytes.toString('hex');
        const newApiKey = 'umy_sk_' + keyHex;

        const keySql = "INSERT INTO api_keys (user_id, api_key, is_active) VALUES (?, ?, TRUE)";
        await connection.execute(keySql, [newUserId, newApiKey]);

        await connection.commit(); 

        res.json({
            success: true,
            message: 'User dan API Key berhasil dibuat.',
            apiKey: newApiKey 
        });

    } catch (error) {
        await connection.rollback(); 
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ success: false, message: 'Email sudah terdaftar.' });
        }
        console.error('Error saat pendaftaran user:', error.message);
        res.status(500).json({ success: false, message: 'Gagal membuat user dan API key.' });
    } finally {
        connection.release(); 
    }
});


app.listen(port, () => {
    console.log(`Server Express berjalan di http://localhost:${port}`);
});