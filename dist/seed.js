"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
require("dotenv/config");
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const prisma_1 = __importDefault(require("./lib/prisma"));
const rbac_1 = require("./utils/rbac");
async function seed() {
    console.log('\n🌱 Seeding database...\n');
    await (0, rbac_1.ensureDefaultRoles)();
    console.log('✅ Default RBAC roles initialized: admin, teacher, hr, student');
    // Seed default departments
    const defaultDepartments = [
        { name: 'Administration', code: 'ADMIN', description: 'System administration & leadership' },
        { name: 'Human Resources', code: 'HR', description: 'People operations & attendance compliance' },
        { name: 'Computer Science', code: 'CS', description: 'Computer Science & Software Engineering' },
        { name: 'Electrical Engineering', code: 'EE', description: 'Electrical & Electronic Engineering' },
    ];
    for (const d of defaultDepartments) {
        await prisma_1.default.department.upsert({
            where: { name: d.name },
            update: { code: d.code, description: d.description },
            create: d,
        });
    }
    console.log('✅ Departments initialized:', defaultDepartments.map((d) => d.name).join(', '));
    // Admin User
    const adminEmail = 'admin@admin.com';
    const adminPassword = await bcryptjs_1.default.hash('admin123', 12);
    const admin = await prisma_1.default.user.upsert({
        where: { email: adminEmail },
        update: {},
        create: {
            name: 'Super Admin',
            email: adminEmail,
            password: adminPassword,
            role: 'admin',
            department: 'Administration',
        },
    });
    console.log(`✅ Admin: ${admin.email} (password: admin123)`);
    // Sample HR User
    const hrPassword = await bcryptjs_1.default.hash('hr123', 12);
    const hrUser = await prisma_1.default.user.upsert({
        where: { email: 'hr@school.com' },
        update: { role: 'hr', department: 'Human Resources' },
        create: {
            name: 'Sarah HR',
            email: 'hr@school.com',
            password: hrPassword,
            role: 'hr',
            department: 'Human Resources',
        },
    });
    console.log(`✅ HR: ${hrUser.name} <${hrUser.email}> [${hrUser.department}] (password: hr123)`);
    // Sample Teachers (department-wise)
    const teacherPassword = await bcryptjs_1.default.hash('teacher123', 12);
    const csTeacher = await prisma_1.default.user.upsert({
        where: { email: 'teacher.cs@school.com' },
        update: { department: 'Computer Science', role: 'teacher' },
        create: {
            name: 'Prof. Alan Turing',
            email: 'teacher.cs@school.com',
            password: teacherPassword,
            role: 'teacher',
            department: 'Computer Science',
        },
    });
    console.log(`✅ Teacher: ${csTeacher.name} <${csTeacher.email}> [${csTeacher.department}] (password: teacher123)`);
    const eeTeacher = await prisma_1.default.user.upsert({
        where: { email: 'teacher.ee@school.com' },
        update: { department: 'Electrical Engineering', role: 'teacher' },
        create: {
            name: 'Dr. Nikola Tesla',
            email: 'teacher.ee@school.com',
            password: teacherPassword,
            role: 'teacher',
            department: 'Electrical Engineering',
        },
    });
    console.log(`✅ Teacher: ${eeTeacher.name} <${eeTeacher.email}> [${eeTeacher.department}] (password: teacher123)`);
    // Sample Students assigned to Teachers & Departments
    const students = [
        {
            name: 'Alice Johnson',
            email: 'alice@student.com',
            password: 'student123',
            department: 'Computer Science',
            teacherId: csTeacher.id,
        },
        {
            name: 'Bob Smith',
            email: 'bob@student.com',
            password: 'student123',
            department: 'Computer Science',
            teacherId: csTeacher.id,
        },
        {
            name: 'Carol White',
            email: 'carol@student.com',
            password: 'student123',
            department: 'Electrical Engineering',
            teacherId: eeTeacher.id,
        },
    ];
    for (const s of students) {
        const hashed = await bcryptjs_1.default.hash(s.password, 12);
        const user = await prisma_1.default.user.upsert({
            where: { email: s.email },
            update: { department: s.department, teacherId: s.teacherId, role: 'student' },
            create: {
                name: s.name,
                email: s.email,
                password: hashed,
                role: 'student',
                department: s.department,
                teacherId: s.teacherId,
            },
        });
        console.log(`✅ Student: ${user.name} <${user.email}> [${user.department}] (password: ${s.password})`);
    }
    console.log('\n───────────────────────────────────────────────');
    console.log('🚀 Seed complete! Start the server with: npm run dev');
    console.log('🔑 Portal login: http://localhost:3000/admin/login');
    console.log('───────────────────────────────────────────────\n');
}
seed()
    .catch((err) => {
    console.error('Seed failed:', err);
    process.exit(1);
})
    .finally(async () => {
    await prisma_1.default.$disconnect();
});
//# sourceMappingURL=seed.js.map