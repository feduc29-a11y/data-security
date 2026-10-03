# Data Security — Render + Supabase

A real full-stack private file-storage app.

## Features

- Real Supabase Auth
- Register + Login
- Server-side referral code validation (`404` by default)
- Empty dashboard for new accounts
- Real file uploads to private Supabase Storage
- File metadata in Postgres
- Download using short-lived signed URLs
- Trash / restore / permanent delete
- Client groups
- Activity logs
- Secure share links with optional expiration, password and download limit
- Admin panel
- Enable/disable users
- Delete users and their files
- Responsive Android + desktop UI
- Render Web Service deployment
- No uploaded files stored on Render's ephemeral filesystem

Supabase Auth handles password storage/hashing. Keep the Supabase service-role key only on the Render server.

## 1. Create Supabase project

Create a Supabase project.

Open SQL Editor and run:

`supabase.sql`

The SQL creates the application tables, RLS configuration and private `user-files` storage bucket.

## 2. Render

Push this project to GitHub.

Create a Render **Web Service** from the repository.

Build command:

`npm install`

Start command:

`npm start`

The included `render.yaml` can also be used as a Blueprint.

## 3. Render environment variables

Set:

- `SUPABASE_URL`
- `SUPABASE_ANON_KEY`
- `SUPABASE_SERVICE_ROLE_KEY`
- `REFERRAL_CODE=404`
- `ADMIN_USERNAME=admin`
- `ADMIN_EMAIL=your-admin-email@example.com`
- `ADMIN_PASSWORD=your-strong-admin-password`
- `BOOTSTRAP_SECRET=your-long-random-bootstrap-secret`
- `STORAGE_BUCKET=user-files`
- `MAX_FILE_SIZE_MB=100`

Do not put the service-role key, admin password, or bootstrap secret in frontend files.

## 4. Create the admin

After the Render service is deployed, send a POST request to:

`https://YOUR-APP.onrender.com/api/bootstrap-admin`

with header:

`x-bootstrap-secret: YOUR_BOOTSTRAP_SECRET`

Example:

`curl -X POST https://YOUR-APP.onrender.com/api/bootstrap-admin -H "x-bootstrap-secret: YOUR_BOOTSTRAP_SECRET"`

The response should say `Admin created.`

Then sign in with:

Username: `admin`

Password: the value of `ADMIN_PASSWORD`

## 5. Register normal users

Use the Register tab.

Required:

- username
- email
- password
- confirm password
- referral code

Default referral code:

`404`

The referral check happens on the Render backend, not only in browser JavaScript.

## Important security notes

- Supabase publishable/anon key can be present in browser code when RLS is correctly configured.
- Never expose `SUPABASE_SERVICE_ROLE_KEY` in HTML, CSS, JavaScript, GitHub, or client-side environment variables.
- The application does not use localStorage as the database or file storage.
- Render's local filesystem should not be treated as permanent upload storage; files are stored in Supabase Storage.
- New users start with no fake/demo files.
