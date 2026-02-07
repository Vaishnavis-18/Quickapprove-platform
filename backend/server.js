const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads'));

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/gov_simplify', {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('MongoDB connected'))
.catch(err => console.log('MongoDB connection error:', err));

// Models

// User Model
const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { 
        type: String, 
        required: true,
        enum: ['entrepreneur', 'officer', 'admin']
    },
    department: { type: String, default: '' }, // For officers
    phone: { type: String, default: '' },
    company: { type: String, default: '' },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);

// Application Model
const ApplicationSchema = new mongoose.Schema({
    applicationId: { type: String, unique: true, required: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    type: { type: String, required: true },
    title: { type: String, required: true },
    description: { type: String, required: true },
    departments: [{ type: String, required: true }],
    status: { 
        type: String, 
        default: 'pending',
        enum: ['pending', 'under_review', 'approved', 'rejected', 'changes_requested']
    },
    currentDepartment: { type: String, default: '' },
    documents: [{ 
        name: String,
        path: String,
        uploadedAt: Date
    }],
    timeline: [{
        department: String,
        action: String,
        officer: String,
        comments: String,
        date: { type: Date, default: Date.now }
    }],
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const Application = mongoose.model('Application', ApplicationSchema);

// Department Model
const DepartmentSchema = new mongoose.Schema({
    name: { type: String, required: true, unique: true },
    description: { type: String },
    officers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    createdAt: { type: Date, default: Date.now }
});

const Department = mongoose.model('Department', DepartmentSchema);

// File upload configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 } // 10MB limit
});

// JWT Authentication middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Access token required' });

    jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
};

// Generate Application ID
const generateApplicationId = () => {
    const date = new Date();
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const random = Math.floor(1000 + Math.random() * 9000);
    return `APP-${year}${month}-${random}`;
};

// Routes

// 1. Auth Routes
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password, role, department, phone, company } = req.body;

        // Check if user exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'Email already registered' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create user
        const user = new User({
            name,
            email,
            password: hashedPassword,
            role,
            department: role === 'officer' ? department : '',
            phone,
            company
        });

        await user.save();

        // Generate JWT token
        const token = jwt.sign(
            { id: user._id, email: user.email, role: user.role },
            process.env.JWT_SECRET || 'your-secret-key',
            { expiresIn: '7d' }
        );

        res.status(201).json({
            success: true,
            message: 'Registration successful',
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role,
                department: user.department
            },
            token
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password, role } = req.body;

        // Find user
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Check role
        if (role && user.role !== role) {
            return res.status(401).json({ error: `User is not a ${role}` });
        }

        // Check password
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Generate JWT token
        const token = jwt.sign(
            { id: user._id, email: user.email, role: user.role },
            process.env.JWT_SECRET || 'your-secret-key',
            { expiresIn: '7d' }
        );

        res.json({
            success: true,
            message: 'Login successful',
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role,
                department: user.department,
                phone: user.phone,
                company: user.company
            },
            token
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 2. Application Routes
app.post('/api/applications', authenticateToken, async (req, res) => {
    try {
        const { type, title, description, departments } = req.body;
        
        // Generate unique application ID
        let applicationId;
        let isUnique = false;
        
        while (!isUnique) {
            applicationId = generateApplicationId();
            const existingApp = await Application.findOne({ applicationId });
            if (!existingApp) isUnique = true;
        }

        const application = new Application({
            applicationId,
            userId: req.user.id,
            type,
            title,
            description,
            departments,
            currentDepartment: departments[0] || '',
            timeline: [{
                department: 'System',
                action: 'Application Submitted',
                officer: 'System',
                comments: 'Application created and submitted successfully',
                date: new Date()
            }]
        });

        await application.save();

        // Populate user details
        await application.populate('userId', 'name email');

        res.status(201).json({
            success: true,
            message: 'Application submitted successfully',
            application
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/applications', authenticateToken, async (req, res) => {
    try {
        let applications;
        
        if (req.user.role === 'entrepreneur') {
            // Entrepreneurs see their own applications
            applications = await Application.find({ userId: req.user.id })
                .populate('userId', 'name email')
                .sort({ createdAt: -1 });
        } else if (req.user.role === 'officer') {
            // Officers see applications for their department
            const user = await User.findById(req.user.id);
            applications = await Application.find({ 
                currentDepartment: user.department,
                status: { $in: ['pending', 'under_review', 'changes_requested'] }
            })
            .populate('userId', 'name email company')
            .sort({ createdAt: -1 });
        } else if (req.user.role === 'admin') {
            // Admins see all applications
            applications = await Application.find()
                .populate('userId', 'name email')
                .sort({ createdAt: -1 });
        }

        res.json({
            success: true,
            applications
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/applications/:id', authenticateToken, async (req, res) => {
    try {
        const application = await Application.findById(req.params.id)
            .populate('userId', 'name email phone company');

        if (!application) {
            return res.status(404).json({ error: 'Application not found' });
        }

        res.json({
            success: true,
            application
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/applications/:id/status', authenticateToken, async (req, res) => {
    try {
        const { status, comments, nextDepartment } = req.body;
        
        const application = await Application.findById(req.params.id);
        if (!application) {
            return res.status(404).json({ error: 'Application not found' });
        }

        // Update status
        application.status = status;
        application.updatedAt = new Date();

        // Add to timeline
        const user = await User.findById(req.user.id);
        application.timeline.push({
            department: user.department || 'System',
            action: status.replace('_', ' ').toUpperCase(),
            officer: user.name,
            comments: comments || '',
            date: new Date()
        });

        // Move to next department if applicable
        if (nextDepartment && application.status === 'under_review') {
            application.currentDepartment = nextDepartment;
        }

        await application.save();

        res.json({
            success: true,
            message: 'Application status updated',
            application
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 3. Department Routes
app.get('/api/departments', authenticateToken, async (req, res) => {
    try {
        const departments = await Department.find().populate('officers', 'name email');
        res.json({
            success: true,
            departments
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/departments', authenticateToken, async (req, res) => {
    try {
        // Only admins can create departments
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Access denied' });
        }

        const { name, description } = req.body;
        const department = new Department({ name, description });
        await department.save();

        res.status(201).json({
            success: true,
            message: 'Department created successfully',
            department
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 4. File Upload Route
app.post('/api/upload', authenticateToken, upload.single('document'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        res.json({
            success: true,
            message: 'File uploaded successfully',
            file: {
                name: req.file.originalname,
                path: `/uploads/${req.file.filename}`,
                size: req.file.size
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 5. User Profile Routes
app.get('/api/profile', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        res.json({
            success: true,
            user
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/profile', authenticateToken, async (req, res) => {
    try {
        const updates = req.body;
        
        // Remove password from updates if present
        delete updates.password;
        delete updates.email;
        delete updates.role;

        const user = await User.findByIdAndUpdate(
            req.user.id,
            updates,
            { new: true, runValidators: true }
        ).select('-password');

        res.json({
            success: true,
            message: 'Profile updated successfully',
            user
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 6. Dashboard Statistics
app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
    try {
        let stats = {};

        if (req.user.role === 'entrepreneur') {
            const applications = await Application.find({ userId: req.user.id });
            stats = {
                total: applications.length,
                pending: applications.filter(app => app.status === 'pending').length,
                under_review: applications.filter(app => app.status === 'under_review').length,
                approved: applications.filter(app => app.status === 'approved').length,
                rejected: applications.filter(app => app.status === 'rejected').length
            };
        } else if (req.user.role === 'officer') {
            const user = await User.findById(req.user.id);
            const applications = await Application.find({ 
                currentDepartment: user.department 
            });
            stats = {
                total: applications.length,
                pending: applications.filter(app => app.status === 'pending').length,
                under_review: applications.filter(app => app.status === 'under_review').length,
                approved: applications.filter(app => app.status === 'approved').length
            };
        } else if (req.user.role === 'admin') {
            const totalApplications = await Application.countDocuments();
            const totalUsers = await User.countDocuments();
            const totalDepartments = await Department.countDocuments();
            
            stats = {
                totalApplications,
                totalUsers,
                totalDepartments,
                pendingApplications: await Application.countDocuments({ status: 'pending' })
            };
        }

        res.json({
            success: true,
            stats
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 7. Seed initial data (for development)
app.post('/api/seed', async (req, res) => {
    try {
        // Create sample departments
        const departments = [
            { name: 'Commerce Department', description: 'Handles business registrations and trade licenses' },
            { name: 'Tax Department', description: 'Manages tax registrations and filings' },
            { name: 'Urban Development', description: 'Handles construction permits and land use' },
            { name: 'Environment Department', description: 'Manages environmental clearances' },
            { name: 'Health Department', description: 'Handles food and health-related licenses' }
        ];

        await Department.deleteMany({});
        await Department.insertMany(departments);

        // Create admin user if not exists
        const adminExists = await User.findOne({ email: 'admin@govsimplify.com' });
        if (!adminExists) {
            const hashedPassword = await bcrypt.hash('admin123', 10);
            const admin = new User({
                name: 'System Admin',
                email: 'admin@govsimplify.com',
                password: hashedPassword,
                role: 'admin'
            });
            await admin.save();
        }

        res.json({
            success: true,
            message: 'Database seeded successfully'
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`API available at http://localhost:${PORT}/api`);
});
