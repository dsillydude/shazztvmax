/* * =================================================================
 * SHAZZ TV MAX Backend Server - v2.4 (URL-based Banners)
 * -----------------------------------------------------------------
 * Patched banner creation/update to accept an image URL
 * instead of a file upload.
 * =================================================================
 */

const express = require('express');
const mongoose = require('mongoose');
const Joi = require('joi');
const cors = require('cors');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const axios = require('axios');
const crypto = require('crypto');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();

// --- Middleware ------------------------------------------------------------
app.use(helmet());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['https://kijiwenitvmax.onrender.com', 'https://kijiwenitvmax.onrender.com'],
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));

// Static file serving for uploaded images
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// --- MongoDB Connection ----------------------------------------------------
// 1. NEW: Database schema for storing settings
const SettingSchema = new mongoose.Schema({
  key: { type: String, unique: true, required: true },
  value: { type: mongoose.Schema.Types.Mixed, required: true },
});
const Setting = mongoose.model('Setting', SettingSchema);

// 2. NEW: Function to load settings from DB on startup
async function loadSettingsFromDatabase() {
  try {
    const plansSetting = await Setting.findOne({ key: 'subscriptionPlans' });
    if (plansSetting) {
      // If plans exist in the DB, use them
      SUBSCRIPTION_PLANS = plansSetting.value;
      console.log('✅ Subscription plans loaded from database.');
    } else {
      // If not, save the default hardcoded plans to the DB for the first time
      await new Setting({ key: 'subscriptionPlans', value: SUBSCRIPTION_PLANS }).save();
      console.log('✅ Default subscription plans saved to database for the first time.');
    }
  } catch (error) {
    console.error('❌ Failed to load settings from database:', error);
  }
}

// --- MongoDB Connection ----------------------------------------------------
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://mackdsilly1:Ourfam2019@shazztvmax.qfisgkc.mongodb.net/?retryWrites=true&w=majority&appName=ShazzTvMax';

mongoose.connect(MONGODB_URI)
  .then(() => {
    console.log('✅ Connected to MongoDB');
    loadSettingsFromDatabase(); // Load settings after connecting to DB
  })
  .catch(err => console.error('❌ MongoDB connection error:', err));

// --- Constants & Config for Paywall ------------------------------------
const TRIAL_MINUTES = 0;
// This is now just a default, the DB will be the source of truth.
let SUBSCRIPTION_PLANS = {
    weekly: { durationDays: 7, amount: 1000 },
    monthly: { durationDays: 30, amount: 3000 },
    yearly: { durationDays: 365, amount: 30000 },
};

// --- Database Models -------------------------------------------------------

// User Schema
const UserSchema = new mongoose.Schema({
  id: { type: String, default: uuidv4, unique: true },
  email: { type: String, unique: true, sparse: true },
  password: { type: String },
  phoneNumber: { type: String },
  deviceId: { type: String, unique: true, required: true },
  isPremium: { type: Boolean, default: false },
  premiumExpiryDate: { type: Date },
  createdAt: { type: Date, default: Date.now },
  lastLogin: { type: Date },
  isActive: { type: Boolean, default: true }
});
const User = mongoose.model('User', UserSchema);

// Admin Schema
const AdminSchema = new mongoose.Schema({
  id: { type: String, default: uuidv4, unique: true },
  username: { type: String, unique: true, required: true },
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['admin', 'super_admin'], default: 'admin' },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
  lastLogin: { type: Date }
});
const Admin = mongoose.model('Admin', AdminSchema);

// Channel Schema
const ChannelSchema = new mongoose.Schema({
  channelId: { type: String, unique: true, required: true },
  name: { type: String, required: true },
  description: { type: String },
  category: { type: String, required: true },
  playbackUrl: { type: String },
  drm: {
    enabled: { type: Boolean },
    provider: { type: String },
    key: { type: String },
  },
  thumbnailUrl: { type: String },
  isPremium: { type: Boolean, default: false },
  isActive: { type: Boolean, default: true },
  position: { type: Number, default: 0 },
  assignedContent: [{ type: String }], // Array of content IDs
  createdAt: { type: Date, default: Date.now }
});
const Channel = mongoose.model('Channel', ChannelSchema);

// Content Schema
const ContentSchema = new mongoose.Schema({
  id: { type: String, default: uuidv4, unique: true },
  title: { type: String, required: true },
  description: { type: String },
  type: { type: String, enum: ['movie', 'series', 'episode'], required: true },
  category: { type: String, required: true },
  streamUrl: { type: String, required: true },
  drmEnabled: { type: Boolean, default: false },
  drmKeyId: { type: String },
  drmKey: { type: String },
  thumbnailUrl: { type: String },
  posterUrl: { type: String },
  duration: { type: Number },
  releaseYear: { type: Number },
  rating: { type: Number, min: 0, max: 10 },
  isPremium: { type: Boolean, default: false },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});
const Content = mongoose.model('Content', ContentSchema);

// Hero Banner Schema
const HeroBannerSchema = new mongoose.Schema({
  id: { type: String, default: uuidv4, unique: true },
  title: { type: String, required: true },
  description: { type: String },
  imageUrl: { type: String, required: true },
  actionType: { type: String, enum: ['channel', 'content', 'external'], required: true },
  actionValue: { type: String }, // channelId, contentId, or external URL
  isActive: { type: Boolean, default: true },
  position: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});
const HeroBanner = mongoose.model('HeroBanner', HeroBannerSchema);

// Payment Schema
const PaymentSchema = new mongoose.Schema({
  orderId: { type: String, required: true, unique: true }, 
  userId: { type: String, required: true },
  customerName: { type: String },
  amount: { type: Number, required: true },
  currency: { type: String, default: 'TZS' },
  paymentMethod: { type: String, default: 'ZenoPay' },
  zenoTransactionId: { type: String }, 
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
  subscriptionType: { type: String, enum: ['weekly', 'monthly', 'yearly'], required: true },
  createdAt: { type: Date, default: Date.now }
});
const Payment = mongoose.model('Payment', PaymentSchema);

// --- Helper Functions ------------------------------------------------------

function transformDoc(doc) {
  if (!doc) return null;
  const obj = doc.toObject ? doc.toObject() : { ...doc };

  const isChannel = obj.hasOwnProperty('channelId') || obj.hasOwnProperty('playbackUrl') || obj.hasOwnProperty('position');

  if (isChannel) {
    if (!obj.playbackUrl && obj.streamUrl) {
      obj.playbackUrl = obj.streamUrl;
    }

    if (!obj.drm) {
      obj.drm = {
        enabled: obj.drmEnabled || false,
        key: obj.drmKey || null,
        provider: null
      };
    }
    delete obj.drmEnabled;
    delete obj.drmKey;
  }

  delete obj.password;
  delete obj.__v;
  delete obj._id;

  return obj;
}

function transformArray(docs) {
  return (docs || []).map(transformDoc);
}

// Generate JWT Token
function generateToken(user, isAdmin = false) {
  const payload = isAdmin ? {
    adminId: user.id || user._id,
    username: user.username,
    role: user.role
  } : {
    userId: user.id || user._id,
    deviceId: user.deviceId,
    isPremium: user.isPremium
  };

  return jwt.sign(payload, process.env.JWT_SECRET, { 
    expiresIn: process.env.JWT_EXPIRES_IN || '7d' 
  });
}

// Middleware to verify JWT token
function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
}

// Middleware to verify admin token
function authenticateAdmin(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Admin access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired admin token' });
    }

    if (!decoded.adminId) {
      return res.status(403).json({ error: 'Admin access required' });
    }

    try {
      const admin = await Admin.findOne({ id: decoded.adminId, isActive: true });
      if (!admin) {
        return res.status(403).json({ error: 'Admin not found or inactive' });
      }

      req.admin = decoded;
      next();
    } catch (error) {
      return res.status(500).json({ error: 'Internal server error' });
    }
  });
}

// Multer configuration for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/');
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB limit
  },
  fileFilter: function (req, file, cb) {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed!'), false);
    }
  }
});

// --- API Routes ------------------------------------------------------------

// --- App Configuration ---
// For now, we store this in memory. For a real app, you would store this in a new 'settings' collection in your database.
let appSettings = {
  whatsappLink: 'https://wa.me/255712345678' // <-- SET YOUR DEFAULT WHATSAPP NUMBER HERE
};

// PUBLIC ENDPOINT: For the main app to get the config
app.get('/api/config', (req, res) => {
  res.json(appSettings);
});

// ADMIN ENDPOINT: For the admin panel to update the config
app.put('/api/admin/config', authenticateAdmin, (req, res) => {
  const { whatsappLink } = req.body;
  if (whatsappLink) {
    appSettings.whatsappLink = whatsappLink;
  }
  res.json({ message: 'Settings updated successfully', settings: appSettings });
});


// --- NEW: Public endpoint for the main app to fetch subscription plans ---
app.get('/api/subscriptions/plans', async (req, res) => {
  try {
    // We try to find the plans saved in the database first.
    const plansSetting = await Setting.findOne({ key: 'subscriptionPlans' });

    if (plansSetting && plansSetting.value) {
      // If found in DB, return them
      console.log('✅ Sent subscription plans from database.');
      return res.json({ plans: plansSetting.value });
    } else {
      // As a fallback, if nothing is in the DB, return the default hardcoded plans.
      console.log('⚠️ Sent default (fallback) subscription plans.');
      return res.json({ plans: SUBSCRIPTION_PLANS });
    }
  } catch (error) {
    console.error('❌ Error fetching subscription plans:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Health Check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    message: 'SHAZZ TV MAX Backend is running',
    timestamp: new Date().toISOString()
  });
});

// --- Authentication Routes (Existing) --------------------------------------

app.post('/api/auth/device-login', async (req, res) => {
    try {
        const { deviceId } = req.body;
        let user = await User.findOne({ deviceId });

        if (user) {
            user.lastLogin = new Date();
            await user.save();
        } else {
            user = new User({
                deviceId: deviceId,
                lastLogin: new Date(),
                isPremium: false
            });
            await user.save();
        }

        const token = generateToken(user);
        res.json({
            message: 'Login successful',
            user: transformDoc(user),
            token
        });
    } catch (error) {
        console.error('Device login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const user = await User.findOne({ id: req.user.userId });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ user: transformDoc(user) });
  } catch (error) {
    console.error('Profile fetch error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- Admin Authentication Routes -------------------------------------------

app.post('/api/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const admin = await Admin.findOne({ 
      $or: [{ username }, { email: username }],
      isActive: true 
    });

    if (!admin) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const isValidPassword = await bcrypt.compare(password, admin.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    admin.lastLogin = new Date();
    await admin.save();

    const token = generateToken(admin, true);
    res.json({
      message: 'Admin login successful',
      admin: transformDoc(admin),
      token
    });
  } catch (error) {
    console.error('Admin login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/admin/me', authenticateAdmin, async (req, res) => {
  try {
    const admin = await Admin.findOne({ id: req.admin.adminId });
    if (!admin) {
      return res.status(404).json({ error: 'Admin not found' });
    }
    res.json({ admin: transformDoc(admin) });
  } catch (error) {
    console.error('Admin profile fetch error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- Admin User Management Routes ------------------------------------------
app.get('/api/admin/users', authenticateAdmin, async (req, res) => {
  try {
    const { 
      page = 1, 
      limit = 20, 
      search = '', 
      isPremium, 
      isActive,
      sortBy = 'createdAt',
      sortOrder = 'desc'
    } = req.query;

    const filter = {};
    
    if (search) {
      filter.$or = [
        { email: { $regex: search, $options: 'i' } },
        { phoneNumber: { $regex: search, $options: 'i' } },
        { deviceId: { $regex: search, $options: 'i' } }
      ];
    }

    if (isPremium !== undefined) {
      filter.isPremium = isPremium === 'true';
    }

    if (isActive !== undefined) {
      filter.isActive = isActive === 'true';
    }

    const sort = {};
    sort[sortBy] = sortOrder === 'desc' ? -1 : 1;

    const skip = (parseInt(page) - 1) * parseInt(limit);

    const [users, total] = await Promise.all([
      User.find(filter)
        .sort(sort)
        .skip(skip)
        .limit(parseInt(limit)),
      User.countDocuments(filter)
    ]);

    res.json({
      users: transformArray(users),
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    console.error('Users fetch error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/admin/users/stats', authenticateAdmin, async (req, res) => {
  try {
    const [
      totalUsers,
      activeUsers,
      premiumUsers,
      newUsersToday,
      newUsersThisWeek,
      newUsersThisMonth
    ] = await Promise.all([
      User.countDocuments(),
      User.countDocuments({ isActive: true }),
      User.countDocuments({ isPremium: true }),
      User.countDocuments({ 
        createdAt: { $gte: new Date(new Date().setHours(0, 0, 0, 0)) }
      }),
      User.countDocuments({ 
        createdAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
      }),
      User.countDocuments({ 
        createdAt: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) }
      })
    ]);

    res.json({
      totalUsers,
      activeUsers,
      premiumUsers,
      inactiveUsers: totalUsers - activeUsers,
      freeUsers: totalUsers - premiumUsers,
      newUsersToday,
      newUsersThisWeek,
      newUsersThisMonth
    });
  } catch (error) {
    console.error('User stats error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/admin/users/:id/premium', authenticateAdmin, async (req, res) => {
  try {
    const { isPremium, subscriptionType = 'monthly' } = req.body;
    const user = await User.findOne({ id: req.params.id });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    user.isPremium = isPremium;

    if (isPremium && subscriptionType) {
      const plan = SUBSCRIPTION_PLANS[subscriptionType];
      if (plan) {
        const now = new Date();
        const startDate = user.premiumExpiryDate > now ? user.premiumExpiryDate : now;
        user.premiumExpiryDate = new Date(startDate.getTime() + plan.durationDays * 24 * 60 * 60 * 1000);
      }
    } else if (!isPremium) {
      user.premiumExpiryDate = null;
    }

    await user.save();

    res.json({
      message: `User ${isPremium ? 'upgraded to' : 'downgraded from'} premium`,
      user: transformDoc(user)
    });
  } catch (error) {
    console.error('User premium update error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/admin/users/:id/status', authenticateAdmin, async (req, res) => {
  try {
    const { isActive } = req.body;
    const user = await User.findOneAndUpdate(
      { id: req.params.id },
      { isActive },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      message: `User ${isActive ? 'unblocked' : 'blocked'} successfully`,
      user: transformDoc(user)
    });
  } catch (error) {
    console.error('User status update error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/admin/users/:id', authenticateAdmin, async (req, res) => {
  try {
    const { email, phoneNumber } = req.body;
    const updateData = {};

    if (email !== undefined) updateData.email = email;
    if (phoneNumber !== undefined) updateData.phoneNumber = phoneNumber;

    const user = await User.findOneAndUpdate(
      { id: req.params.id },
      updateData,
      { new: true }
    );

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      message: 'User updated successfully',
      user: transformDoc(user)
    });
  } catch (error) {
    console.error('User update error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- Admin Subscription Management Routes ----------------------------------
app.get('/api/admin/subscriptions', authenticateAdmin, (req, res) => {
  res.json({
    plans: SUBSCRIPTION_PLANS
  });
});

app.put('/api/admin/subscriptions', authenticateAdmin, async (req, res) => {
  try {
    const { plans } = req.body;

    if (!plans || typeof plans !== 'object') {
      return res.status(400).json({ error: 'Invalid plans data' });
    }

    // Validation (no change)
    for (const [key, plan] of Object.entries(plans)) {
      if (!plan.durationDays || !plan.amount || typeof plan.durationDays !== 'number' || typeof plan.amount !== 'number') {
        return res.status(400).json({ error: `Invalid plan structure for ${key}` });
      }
    }

    // Save the updated plans to the database
    await Setting.findOneAndUpdate(
        { key: 'subscriptionPlans' },
        { value: plans },
        { upsert: true, new: true } // upsert:true creates the document if it doesn't exist
    );

    // Also update the in-memory variable for immediate access
    SUBSCRIPTION_PLANS = plans;

    res.json({
      message: 'Subscription plans updated and saved successfully',
      plans: SUBSCRIPTION_PLANS
    });
  } catch (error) {
    console.error('Subscription update error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/admin/payments/stats', authenticateAdmin, async (req, res) => {
  try {
    const [
      totalPayments,
      completedPayments,
      pendingPayments,
      failedPayments,
      totalRevenue,
      revenueThisMonth
    ] = await Promise.all([
      Payment.countDocuments(),
      Payment.countDocuments({ status: 'completed' }),
      Payment.countDocuments({ status: 'pending' }),
      Payment.countDocuments({ status: 'failed' }),
      Payment.aggregate([
        { $match: { status: 'completed' } },
        { $group: { _id: null, total: { $sum: '$amount' } } }
      ]),
      Payment.aggregate([
        { 
          $match: { 
            status: 'completed',
            createdAt: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) }
          } 
        },
        { $group: { _id: null, total: { $sum: '$amount' } } }
      ])
    ]);

    res.json({
      totalPayments,
      completedPayments,
      pendingPayments,
      failedPayments,
      totalRevenue: totalRevenue[0]?.total || 0,
      revenueThisMonth: revenueThisMonth[0]?.total || 0
    });
  } catch (error) {
    console.error('Payment stats error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/admin/payments', authenticateAdmin, async (req, res) => {
  try {
    const { 
      page = 1, 
      limit = 20, 
      status,
      subscriptionType,
      sortBy = 'createdAt',
      sortOrder = 'desc'
    } = req.query;

    const filter = {};
    
    if (status) filter.status = status;
    if (subscriptionType) filter.subscriptionType = subscriptionType;

    const sort = {};
    sort[sortBy] = sortOrder === 'desc' ? -1 : 1;

    const skip = (parseInt(page) - 1) * parseInt(limit);

    const [payments, total] = await Promise.all([
      Payment.find(filter)
        .sort(sort)
        .skip(skip)
        .limit(parseInt(limit)),
      Payment.countDocuments(filter)
    ]);

    res.json({
      payments: transformArray(payments),
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    console.error('Payments fetch error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- Admin Channel Management Routes (Extended) ----------------------------
app.put('/api/admin/channels/:id/content', authenticateAdmin, async (req, res) => {
  try {
    const { contentIds } = req.body;
    
    if (!Array.isArray(contentIds)) {
      return res.status(400).json({ error: 'contentIds must be an array' });
    }

    const channel = await Channel.findOneAndUpdate(
      { channelId: req.params.id },
      { assignedContent: contentIds },
      { new: true }
    );

    if (!channel) {
      return res.status(404).json({ error: 'Channel not found' });
    }

    res.json({
      message: 'Content assigned to channel successfully',
      channel: transformDoc(channel)
    });
  } catch (error) {
    console.error('Channel content assignment error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- Public Route for Main App to Fetch Banners ---
app.get('/api/banners', async (req, res) => {
  try {
    const banners = await HeroBanner.find({ isActive: true }).sort({ position: 'asc' });
    res.json({
      banners: transformArray(banners),
      total: banners.length
    });
  } catch (error) {
    console.error('Public banners fetch error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- Admin Hero Banner Management Routes -----------------------------------
app.get('/api/admin/banners', authenticateAdmin, async (req, res) => {
  try {
    const { isActive, sortBy = 'position', sortOrder = 'asc' } = req.query;
    const filter = {};
    if (isActive !== undefined) {
      filter.isActive = isActive === 'true';
    }
    const sort = {};
    sort[sortBy] = sortOrder === 'desc' ? -1 : 1;
    const banners = await HeroBanner.find(filter).sort(sort);
    res.json({
      banners: transformArray(banners),
      total: banners.length
    });
  } catch (error) {
    console.error('Banners fetch error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create new hero banner (Patched to use imageUrl)
app.post('/api/admin/banners', authenticateAdmin, async (req, res) => {
  try {
    const { title, description, actionType, actionValue, imageUrl, isActive, position } = req.body;

    if (!title || !actionType || !imageUrl) {
      return res.status(400).json({ error: 'Title, actionType, and imageUrl are required' });
    }

    const banner = new HeroBanner({
      title,
      description,
      imageUrl,
      actionType,
      actionValue,
      isActive: isActive,
      position: position || 0
    });

    await banner.save();

    res.status(201).json({
      message: 'Hero banner created successfully',
      banner: transformDoc(banner)
    });
  } catch (error) {
    console.error('Banner creation error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update hero banner (Patched to use imageUrl)
app.put('/api/admin/banners/:id', authenticateAdmin, async (req, res) => {
  try {
    const { title, description, actionType, actionValue, imageUrl, isActive, position } = req.body;
    
    const updateData = {};
    if (title !== undefined) updateData.title = title;
    if (description !== undefined) updateData.description = description;
    if (actionType !== undefined) updateData.actionType = actionType;
    if (actionValue !== undefined) updateData.actionValue = actionValue;
    if (imageUrl !== undefined) updateData.imageUrl = imageUrl;
    if (isActive !== undefined) updateData.isActive = isActive;
    if (position !== undefined) updateData.position = position || 0;

    const banner = await HeroBanner.findOneAndUpdate(
      { id: req.params.id },
      updateData,
      { new: true }
    );

    if (!banner) {
      return res.status(404).json({ error: 'Banner not found' });
    }

    res.json({
      message: 'Hero banner updated successfully',
      banner: transformDoc(banner)
    });
  } catch (error) {
    console.error('Banner update error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete hero banner
app.delete('/api/admin/banners/:id', authenticateAdmin, async (req, res) => {
  try {
    const banner = await HeroBanner.findOneAndDelete({ id: req.params.id });
    if (!banner) {
      return res.status(404).json({ error: 'Banner not found' });
    }
    res.json({
      message: 'Hero banner deleted successfully'
    });
  } catch (error) {
    console.error('Banner deletion error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


// Image upload endpoint
app.post('/api/admin/upload', authenticateAdmin, upload.single('image'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No image file provided' });
    }

    res.json({
      message: 'Image uploaded successfully',
      imageUrl: `/uploads/${req.file.filename}`,
      filename: req.file.filename
    });
  } catch (error) {
    console.error('Image upload error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- Existing Routes (Content Management, Payment, etc.) -------------------
app.post('/api/users/update-watch-time', authenticateToken, async (req, res) => {
    try {
        const user = await User.findOne({ id: req.user.userId });
        if (!user) return res.status(404).json({ error: 'User not found' });

        if (user.isPremium && (!user.premiumExpiryDate || new Date(user.premiumExpiryDate) > new Date())) {
            return res.json({ success: true, message: 'User is premium.' });
        } else {
            return res.status(402).json({ error: 'PAYWALL', message: 'Premium required to stream.' });
        }
    } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Payment Routes
app.post('/api/payment/initiate-zenopay', authenticateToken, async (req, res) => {
    const { customerName, phoneNumber, subscriptionType } = req.body;
    const user = await User.findOne({ id: req.user.userId });

    if (!customerName || !phoneNumber || !subscriptionType || !SUBSCRIPTION_PLANS[subscriptionType]) {
        return res.status(400).json({ error: 'Invalid request details. Name, phone, and plan are required.' });
    }

    const plan = SUBSCRIPTION_PLANS[subscriptionType];
    const orderId = uuidv4();

    await new Payment({
        orderId,
        userId: user.id,
        customerName: customerName,
        amount: plan.amount,
        subscriptionType,
        status: 'pending',
    }).save();

    const zenoPayload = {
        order_id: orderId,
        buyer_email: user.email || `${user.deviceId}@kijiweni.tv`,
        buyer_name: customerName,
        buyer_phone: phoneNumber,
        amount: plan.amount,
        webhook_url: `${process.env.YOUR_BACKEND_URL}/api/payment/zenopay-webhook`
    };

    try {
        console.log('Sending payment request to ZenoPay:', zenoPayload);
        const zenoResponse = await axios.post(
            'https://zenoapi.com/api/payments/mobile_money_tanzania',
            zenoPayload,
            { headers: { 'x-api-key': process.env.ZENOPAY_API_KEY } }
        );

        console.log('ZenoPay response:', zenoResponse.data);
        res.json({
            success: true,
            message: 'Payment initiated. Please confirm on your phone.',
            orderId: orderId,
        });
    } catch (error) {
        console.error('ZenoPay API error:', error.response ? error.response.data : error.message);
        res.status(500).json({ error: 'Failed to initiate payment.' });
    }
});

app.post('/api/payment/zenopay-webhook', async (req, res) => {
    // Log every incoming webhook attempt to help with debugging
    console.log('--- ZenoPay Webhook Received ---');
    console.log('Headers:', req.headers);
    console.log('Body:', req.body);

   const { order_id, payment_status, reference } = req.body;
if (!order_id || !payment_status) {
    console.warn('Webhook received with missing order_id or payment_status.');
    return res.status(400).send('Bad Request: Missing required fields.');
}
    
    console.log(`Processing webhook for order ${order_id}, status: ${payment_status}`);

    // --- Logic with Error Handling ---
    try {
        if (payment_status === 'COMPLETED') {
            const payment = await Payment.findOne({ orderId: order_id });

            if (!payment) {
                console.warn(`Webhook for unknown Order ID received: ${order_id}. Acknowledging.`);
                return res.status(200).send('Acknowledged (Order not found)');
            }
            if (payment.status === 'completed') {
                console.log(`Webhook for already completed Order ID received: ${order_id}. Acknowledging.`);
                return res.status(200).send('Acknowledged (Already completed)');
            }

            payment.status = 'completed';
            payment.zenoTransactionId = reference;
            await payment.save();
            console.log(`Payment record for ${order_id} updated to 'completed'.`);

            const user = await User.findOne({ id: payment.userId });
            if (user) {
                const plan = SUBSCRIPTION_PLANS[payment.subscriptionType];
                const now = new Date();
                const startDate = user.premiumExpiryDate && user.premiumExpiryDate > now ? user.premiumExpiryDate : now;

                user.isPremium = true;
                user.premiumExpiryDate = new Date(startDate.getTime() + plan.durationDays * 24 * 60 * 60 * 1000);
                await user.save();

                console.log(`SUCCESS: User ${user.id} upgraded to premium. New expiry: ${user.premiumExpiryDate}`);
            } else {
                console.error(`CRITICAL: Could not find user with ID ${payment.userId} for completed payment ${order_id}.`);
            }
        } else {
             console.log(`Received non-completed status '${payment_status}' for order ${order_id}. No action taken.`);
        }

        res.status(200).send('Webhook processed successfully');

    } catch (error) {
        console.error(`CRITICAL ERROR while processing webhook for order ${order_id}:`, error);
        res.status(500).send('Internal Server Error');
    }
});

// Channel CRUD
app.post('/api/channels', authenticateAdmin, async (req, res) => {
    try {
        const newChannel = new Channel(req.body);
        await newChannel.save();
        res.status(201).json({ channel: transformDoc(newChannel) });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.get('/api/channels', async (req, res) => {
  try {
    const { category, premium } = req.query;
    let filter = { isActive: true };
    if (category) filter.category = category;
    if (premium !== undefined) filter.isPremium = premium === 'true';

    const channels = await Channel.find(filter).sort({ position: 1, name: 1 });
    res.json({ channels: transformArray(channels), total: channels.length });
  } catch (error) {
    console.error('Channels fetch error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/channels/:id', authenticateAdmin, async (req, res) => {
    try {
        const channel = await Channel.findOneAndUpdate({ channelId: req.params.id }, req.body, { new: true });
        if (!channel) return res.status(404).json({ error: 'Channel not found' });
        res.json({ channel: transformDoc(channel) });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.delete('/api/channels/:id', authenticateAdmin, async (req, res) => {
    try {
        const channel = await Channel.findOneAndDelete({ channelId: req.params.id });
        if (!channel) return res.status(404).json({ error: 'Channel not found' });
        res.status(200).json({ message: 'Channel deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Content CRUD
app.post('/api/content', authenticateAdmin, async (req, res) => {
    try {
        const newContent = new Content(req.body);
        await newContent.save();
        res.status(201).json({ content: transformDoc(newContent) });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.get('/api/content', async (req, res) => {
  try {
    const { type, category, premium } = req.query;
    let filter = { isActive: true };
    if (type) filter.type = type;
    if (category) filter.category = category;
    if (premium !== undefined) filter.isPremium = premium === 'true';

    const content = await Content.find(filter).sort({ createdAt: -1 });
    res.json({ content: transformArray(content), total: content.length });
  } catch (error) {
    console.error('Content fetch error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/content/:id', authenticateAdmin, async (req, res) => {
    try {
        const content = await Content.findOneAndUpdate({ id: req.params.id }, req.body, { new: true });
        if (!content) return res.status(404).json({ error: 'Content not found' });
        res.json({ content: transformDoc(content) });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.delete('/api/content/:id', authenticateAdmin, async (req, res) => {
    try {
        const content = await Content.findOneAndDelete({ id: req.params.id });
        if (!content) return res.status(404).json({ error: 'Content not found' });
        res.status(200).json({ message: 'Content deleted successfully' });
    } catch (error)
 {
        res.status(500).json({ error: error.message });
    }
});

// Home screen data
app.get('/api/home-screen', async (req, res) => {
  try {
      // Fetch all data in parallel for speed
      const [
        banners,
        sportsChannels,
        tamthiliaChannels,
        allChannels
      ] = await Promise.all([
          HeroBanner.find({ isActive: true }).sort({ position: 'asc' }),
          Channel.find({ isActive: true, category: 'sports' }).sort({ position: 1, name: 1 }).limit(10),
          Channel.find({ isActive: true, category: 'tamthilia' }).sort({ position: 1, name: 1 }).limit(10),
          Channel.find({ isActive: true }).sort({ position: 1, name: 1 })
      ]);

      const sportsChannelIds = sportsChannels.map(c => c.channelId);
      const tamthiliaChannelIds = tamthiliaChannels.map(c => c.channelId);
      const moreChannels = allChannels.filter(c => !sportsChannelIds.includes(c.channelId) && !tamthiliaChannelIds.includes(c.channelId));

      res.json({
          banners: transformArray(banners), // ADDED BANNERS
          sportsChannels: transformArray(sportsChannels),
          tamthiliaContent: transformArray(tamthiliaChannels),
          moreChannels: transformArray(moreChannels)
      });

  } catch (error) {
      console.error('Home screen data fetch error:', error);
      res.status(500).json({ error: 'Internal server error' });
  }
});

// DRM token endpoint
app.post('/api/drm/token', authenticateToken, async (req, res) => {
  console.log("\n--- New Request Received at /api/drm/token ---");

  try {
    const { channelId, contentId } = req.body;
    console.log(`1. Received request body:`, req.body);

    if (!channelId && !contentId) {
      console.log("❌ ERROR: Request body did not contain a channelId or contentId.");
      return res.status(400).json({ error: "channelId or contentId is missing from request" });
    }

    let item;
    if (channelId) {
        console.log(`2. Searching for CHANNEL with channelId: ${channelId}`);
        item = await Channel.findOne({ channelId: channelId });
    } else {
        console.log(`2. Searching for CONTENT with id: ${contentId}`);
        item = await Content.findOne({ id: contentId });
    }

    if (!item) {
      const idUsed = channelId || contentId;
      console.log(`❌ ERROR: Item with ID "${idUsed}" not found in database.`);
      return res.status(404).json({ error: 'Item not found' });
    }

    console.log("3. Found item:", item.name || item.title);
    console.log("4. Sending item data back to the app.");

    res.json({
      success: true,
      data: transformDoc(item),
    });

  } catch (error) {
    console.error("❌ CRITICAL ERROR inside /api/drm/token route:", error);
    return res.status(500).json({ error: "An internal server error occurred." });
  }
});

// Admin seeder
app.post('/api/admin/seed', async (req, res) => {
  try {
    // Create default admin if none exists
    const adminCount = await Admin.countDocuments();
    if (adminCount === 0) {
      const defaultAdmin = new Admin({
        username: 'admin',
        email: 'admin@kijiweni.tv',
        password: await bcrypt.hash('shazz321', 10),
        role: 'super_admin'
      });
      await defaultAdmin.save();
      console.log('Default admin created: username=admin, password=admin123');
    }

    res.json({ success: true, message: 'Seed operation complete.' });
  } catch (error) {
    console.error('Seed data error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- Error Handling & Server Start -----------------------------------------
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ error: 'Internal server error' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 KIJIWENI Backend server v2.4 (URL Banners) running on port ${PORT}`);
});

module.exports = app;