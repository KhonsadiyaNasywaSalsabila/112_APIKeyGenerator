const express = require('express')
const path = require('path')
const crypto = require('crypto')
const app = express()
const port = 3000

// --- BARU: Import mysql2 (gunakan versi promise) ---
const mysql = require('mysql2/promise');

// index.js - PERIKSA BAGIAN INI!
const dbConfig = {
    host: '127.0.0.1',
    port: 3309,
    user: 'root', // Ganti dengan user MySQL Anda
    password: '905.Nasywa', // Ganti dengan password MySQL Anda
    database: 'apikey', // <--- HARUS PERSIS SAMA DENGAN NAMA YANG ANDA BUAT
};


// --- BARU: Buat connection pool ---
// Pool lebih efisien untuk mengelola banyak koneksi
const pool = mysql.createPool(dbConfig);

// (Opsional) Fungsi untuk mengecek koneksi saat startup
async function checkDbConnection() {
    try {
        const connection = await pool.getConnection();
        console.log('Koneksi ke database MySQL berhasil.');
        connection.release(); // Kembalikan koneksi ke pool
    } catch (error) {
        console.error('Gagal terhubung ke database MySQL:', error.message);
        process.exit(1); // Keluar dari aplikasi jika DB gagal konek
    }
}
checkDbConnection(); // Jalankan pengecekan koneksi

// --- TIDAK DIGUNAKAN LAGI ---
// Variabel ini tidak lagi diperlukan karena kita menyimpan di DB
// let latestApiKey = null; 

// Middleware untuk mengurai body request dalam format JSON
app.use(express.json()); 

// 1. Middleware untuk menyajikan file statis dari folder 'public'
app.use(express.static(path.join(__dirname, 'public')));

// 2. Handler untuk permintaan root ('/')
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'))
})

// 3. Handler untuk permintaan POST '/create'
// --- DIMODIFIKASI: Menjadi async dan menyimpan ke DB ---
app.post('/create', async (req, res) => { // <-- tambahkan 'async'
    try {
        const randomBytes = crypto.randomBytes(32);
        const keyHex = randomBytes.toString('hex');
        const newApiKey = 'umy_sk_' + keyHex;

        // --- SIMPAN API KEY KE DATABASE ---
        // Ganti 'latestApiKey = newApiKey;' dengan ini:
        const sql = "INSERT INTO api_keys (api_key) VALUES (?)";
        await pool.execute(sql, [newApiKey]);
        
        console.log(`API Key baru dibuat dan disimpan ke DB: ${newApiKey}`);

        // Mengirim API Key kembali ke klien
        res.json({
            success: true,
            apiKey: newApiKey
        });

    } catch (error) {
        // Menangani error jika terjadi (misal: DB mati, key duplikat)
        console.error('Error saat membuat API key:', error.message);
        res.status(500).json({
            success: false,
            message: 'Gagal membuat API key di server.'
        });
    }
});

// 4. Handler untuk permintaan POST '/checkapi' (Validasi API Key)
// --- DIMODIFIKASI: Menjadi async dan mengecek ke DB ---
app.post('/checkapi', async (req, res) => { // <-- tambahkan 'async'
    const clientKey = req.body.key;

    if (!clientKey) {
        return res.status(400).json({ 
            success: false, 
            message: 'API Key diperlukan di body request (key).' 
        });
    }

    try {
        // --- CEK API KEY KE DATABASE ---
        // Ganti 'clientKey === latestApiKey' dengan ini:
        const sql = "SELECT * FROM api_keys WHERE api_key = ?";
        const [rows] = await pool.execute(sql, [clientKey]);

        // 'rows' adalah array. Jika panjangnya > 0, berarti key ditemukan
        if (rows.length > 0) {
            res.json({
                success: true,
                message: 'API Key valid.'
            });
        } else {
            res.status(401).json({ // 401 Unauthorized
                success: false,
                message: 'API Key tidak valid atau tidak ditemukan.'
            });
        }

    } catch (error) {
        // Menangani error jika terjadi (misal: DB mati)
        console.error('Error saat memvalidasi API key:', error.message);
        res.status(500).json({
            success: false,
            message: 'Gagal memvalidasi API key di server.'
        });
    }
});


app.listen(port, () => {
    console.log(`Server Express berjalan di http://localhost:${port}`)
})

