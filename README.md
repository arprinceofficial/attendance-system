# 📋 Attendance System

A complete daily attendance management system built with **TypeScript**, **Node.js**, **Express**, **Prisma ORM**, and **MongoDB**. Features admin-generated attendance links with optional expiry timers, IP/MAC tracking, and a full admin panel.

---

## ✨ Features

- 🔗 **Admin-Controlled Attendance Links** — no link is generated or printed in the terminal on startup; admins create and manage links directly in the Admin Panel
- ⏱ **Link Expiry Timer** — admins can set a link duration (e.g., 5m, 15m, 30m, 1h, 2h, 4h, 8h, custom minutes, or no expiry) with a live countdown
- 🔐 **Student Authentication** — email + password login through the attendance link
- 📍 **IP & MAC Tracking** — logs IP address and attempts MAC lookup; flags changes from previous sessions
- 🛡️ **Admin Panel** — full SPA dashboard for attendance management
- 👥 **User Management** — create, edit, delete students and admins
- 📊 **History & CSV Export** — view and download attendance records by date
- ⚠️ **Change Detection** — warns admin when a student's IP or MAC differs from their last record

---

## 🗂️ Project Structure

```
Attendance System/
├── prisma/
│   └── schema.prisma             # MongoDB schema
├── src/
│   ├── index.ts                  # Express entry point
│   ├── seed.ts                   # Database seeder (users only)
│   ├── lib/
│   │   └── prisma.ts             # Prisma client singleton
│   ├── types/
│   │   └── index.ts              # Shared TypeScript interfaces
│   ├── routes/
│   │   ├── attend.ts             # Attendance link validation & page routes
│   │   ├── auth.ts               # Student login / attendance marking
│   │   └── admin.ts              # Admin REST API
│   ├── middleware/
│   │   ├── authMiddleware.ts     # Student JWT middleware
│   │   └── adminMiddleware.ts    # Admin JWT middleware
│   └── utils/
│       └── tokenUtils.ts         # Token, date & expiry helpers
├── dist/                         # Compiled JavaScript output (`npm run build`)
├── public/
│   ├── attend.html               # Student attendance page
│   ├── error.html                # Expired/invalid link page
│   └── admin/
│       ├── login.html            # Admin login page
│       └── dashboard.html        # Admin SPA dashboard
├── tsconfig.json
├── .env.example                  # Environment variable template
├── package.json
└── README.md
```

---

## 🚀 Setup & Installation

### 1. Prerequisites

- **Node.js** v18 or later
- **MongoDB** running locally (`mongodb://localhost:27017`) or a MongoDB Atlas URI

### 2. Install Dependencies

```bash
cd "Attendance System"
npm install
```

### 3. Configure Environment

```bash
cp .env.example .env
```

Edit `.env` with your values:

```env
DATABASE_URL="mongodb://localhost:27017/attendance_system"
JWT_SECRET="change-this-to-a-long-random-string"
ADMIN_JWT_SECRET="another-different-long-random-string"
PORT=3000
BASE_URL="http://localhost:3000"
```

### 4. Push Prisma Schema

```bash
npm run db:push
```

### 5. Seed the Database

```bash
npm run seed
```

This creates:
- **Admin user**: `admin@admin.com` / `admin123`
- **Students**: `alice@student.com`, `bob@student.com`, `carol@student.com` (all password: `student123`)

### 6. Build & Start the Server

```bash
# Development (TypeScript via ts-node)
npm run dev

# Production build + start
npm run build
NODE_ENV=production npm start
```

---

## 🌐 Access URLs

| URL | Description |
|-----|-------------|
| `http://localhost:3000/` | Redirects to admin login |
| `http://localhost:3000/admin/login` | Admin login page |
| `http://localhost:3000/admin/dashboard` | Admin dashboard (requires login) |
| `http://localhost:3000/attend/:token` | Student attendance page (created from Admin Panel → Link Manager) |

---

## 🔌 API Reference

### Student Auth

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/auth/login` | Mark attendance (body: `{email, password, token}`) |

### Attendance Link (public)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/attend/:token` | Serve student login page |
| `GET` | `/attend/validate/:token` | Validate token & expiry (JSON response) |

### Admin API (requires `Authorization: Bearer <token>`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/admin/login` | Admin login → returns JWT |
| `GET` | `/api/admin/stats` | Today's stats |
| `GET` | `/api/admin/attendance/today` | Today's attendance records |
| `GET` | `/api/admin/attendance?date=YYYY-MM-DD` | Records by date |
| `POST` | `/api/admin/attendance` | Manual mark `{userId, date}` |
| `PUT` | `/api/admin/attendance/:id` | Update attendance record |
| `DELETE` | `/api/admin/attendance/:id` | Delete attendance record |
| `GET` | `/api/admin/users` | List all users |
| `POST` | `/api/admin/users` | Create user |
| `PUT` | `/api/admin/users/:id` | Update user |
| `DELETE` | `/api/admin/users/:id` | Delete user + their records |
| `GET` | `/api/admin/link` | Get today's active link & link history |
| `POST` | `/api/admin/link/create` | Create new link with optional `durationMinutes` |
| `POST` | `/api/admin/link/deactivate` | Deactivate current active link |

---

## 🏗️ Tech Stack

| Technology | Purpose |
|-----------|---------|
| TypeScript + Node.js + Express | Typed web server & REST API |
| Prisma ORM | Database abstraction |
| MongoDB | Data persistence |
| JWT (jsonwebtoken) | Admin & student auth tokens |
| bcryptjs | Password hashing |
| @network-utils/arp-lookup | Best-effort MAC address resolution |
| Tailwind CSS (CDN) | Frontend styling |
| Vanilla JS | Frontend interactivity |
