# SAYODA CYBER FORCE — Full Admin Backend

## 1) Database
Run `schema-admin.sql` in Neon SQL Editor.

## 2) Environment
Set:
- DATABASE_URL = Neon connection string
- FRONTEND_ORIGIN = exact GitHub Pages origin

## 3) Install/run
npm install
npm start

## 4) Create your admin account
node create-admin.js YOUR_ADMIN_USERNAME YOUR_STRONG_PASSWORD

## 5) Access control
Every video is locked by default. Only rows in `video_access` unlock a video for a user. Admin can grant/revoke access from the Admin Panel.

Never put DATABASE_URL, Neon password, or admin password in GitHub/frontend code.

## Important YouTube limitation
If a video is Public on YouTube, the source can still be discovered outside your platform. Backend access control protects access through SAYODA; true media protection requires private/signed video hosting.
