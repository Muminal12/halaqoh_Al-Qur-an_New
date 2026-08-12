# Deployment singkat

## Render / Railway / VPS
- Upload project ini sebagai Node.js app.
- Build command: `npm install`
- Start command: `npm start`
- Set environment variables dari `.env.example`.
- Pastikan folder `data/` berada pada persistent disk/volume agar database SQLite tidak hilang saat redeploy.
- Gunakan HTTPS.

## Docker
`docker build -t halaqoh-al-quran .`
`docker run -p 3000:3000 --env-file .env -v halaqoh-data:/app/data halaqoh-al-quran`
