# Aplikasi Halaqoh Al Qur'an — Online

Starter project full-stack untuk aplikasi Halaqoh Al Qur'an.

## Fitur
- Login dan registrasi Ustadz.
- Password di-hash dengan bcrypt.
- Session JWT disimpan pada HttpOnly cookie.
- Database SQLite di server.
- Data santri dan setoran terpisah per akun.
- Role `admin` dan `ustadz`.
- Admin dapat membuat akun Ustadz melalui API admin.
- Statistik setoran/murajaah.
- Bisa diakses dari HP/laptop selama server dideploy ke hosting.

## Jalankan lokal
1. Install Node.js 20+.
2. Salin `.env.example` menjadi `.env` dan ubah secret/password.
3. Jalankan `npm install`.
4. Jalankan `npm start`.
5. Buka `http://localhost:3000`.

## Admin
Akun admin dibuat otomatis dari `ADMIN_USERNAME`, `ADMIN_PASSWORD`, dan `ADMIN_NAME` saat server pertama kali dijalankan.

## Deploy
Project ini dapat dideploy ke layanan Node.js yang menyediakan persistent disk/volume untuk file `data/halaqoh.db`. Untuk produksi, gunakan HTTPS dan secret yang panjang/acak.

## Dashboard Admin

Admin memiliki menu tambahan **Dashboard Admin** untuk:
- melihat total ustadz, santri, dan setoran;
- membuat akun ustadz baru;
- mencari akun berdasarkan nama/username;
- melihat jumlah santri, setoran, dan murajaah per akun;
- mengaktifkan atau menonaktifkan akun ustadz.

Akun yang dinonaktifkan tidak dapat login sampai diaktifkan kembali oleh admin.
