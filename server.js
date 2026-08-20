const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
require('dotenv').config();

const app = express();

// Render (and most PaaS hosts) sit behind a reverse proxy. Without this,
// express-rate-limit and req.ip would see the proxy's IP for every request,
// lumping all users into one shared rate-limit bucket.
app.set('trust proxy', 1);

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/landscapeflow')
  .then(() => console.log('MongoDB Connected'))
  .catch(err => console.error('MongoDB Error:', err));

// Cloudinary reads CLOUDINARY_URL from the environment automatically.
const photosEnabled = !!process.env.CLOUDINARY_URL;
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith('image/')) {
      return cb(new Error('Only image files are allowed'));
    }
    cb(null, true);
  }
});

function uploadToCloudinary(buffer) {
  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      { folder: 'landscapeflow' },
      (error, result) => (error ? reject(error) : resolve(result))
    );
    stream.end(buffer);
  });
}

// ---------- Models ----------
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  name: String,
  phone: String,
  role: { type: String, enum: ['admin', 'manager', 'crew'], default: 'crew' }
});

const customerSchema = new mongoose.Schema({
  name: String,
  phone: String,
  email: String,
  notes: String,
  createdAt: { type: Date, default: Date.now }
});

const photoSchema = new mongoose.Schema({
  url: String,
  publicId: String,
  caption: String,
  uploadedBy: String,
  uploadedAt: { type: Date, default: Date.now }
}, { _id: true });

const propertySchema = new mongoose.Schema({
  address: String,
  city: String,
  size: Number,
  manager: String,
  customerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Customer' },
  photos: [photoSchema],
  createdAt: { type: Date, default: Date.now }
});

const scheduleSchema = new mongoose.Schema({
  propertyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Property', required: true },
  date: String, // YYYY-MM-DD, sorts correctly as a string
  time: String,
  crew: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  status: { type: String, enum: ['scheduled', 'in-progress', 'completed', 'cancelled'], default: 'scheduled' },
  notes: String,
  recurrenceGroupId: String,
  createdAt: { type: Date, default: Date.now }
});

const auditLogSchema = new mongoose.Schema({
  action: String,
  targetType: String,
  targetId: String,
  performedBy: String,
  performedByEmail: String,
  details: mongoose.Schema.Types.Mixed,
  timestamp: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Customer = mongoose.model('Customer', customerSchema);
const Property = mongoose.model('Property', propertySchema);
const Schedule = mongoose.model('Schedule', scheduleSchema);
const AuditLog = mongoose.model('AuditLog', auditLogSchema);

// ---------- Helpers ----------
async function logAudit(req, action, targetType, targetId, details) {
  try {
    await AuditLog.create({
      action,
      targetType,
      targetId: String(targetId || ''),
      performedBy: req.user?.id,
      performedByEmail: req.user?.email,
      details
    });
  } catch (error) {
    console.error('Audit log failed:', error.message);
  }
}

function getPagination(req) {
  const page = Math.max(1, parseInt(req.query.page, 10) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 20));
  return { page, limit, skip: (page - 1) * limit };
}

function isValidEmail(str) {
  return typeof str === 'string' && /\S+@\S+\.\S+/.test(str);
}

// Require a valid JWT on protected routes
function authenticate(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET || 'secret');
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

// Admin or manager: allowed to edit data, but not manage users or delete
function requireManagerOrAdmin(req, res, next) {
  if (req.user?.role !== 'admin' && req.user?.role !== 'manager') {
    return res.status(403).json({ error: 'Manager or admin access required' });
  }
  next();
}

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: process.env.NODE_ENV === 'test' ? 1000 : 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Try again in a few minutes.' }
});

// ---------- Config ----------
app.get('/api/config', authenticate, (req, res) => {
  res.json({
    photosEnabled,
    googleMapsApiKey: process.env.GOOGLE_MAPS_API_KEY || null,
    smsEnabled: !!(process.env.TWILIO_SID && process.env.TWILIO_AUTH_TOKEN && process.env.TWILIO_PHONE)
  });
});

// ---------- Auth Routes ----------
app.post('/api/auth/login', loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email/username and password are required' });
    }
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user._id, email: user.email, role: user.role }, process.env.JWT_SECRET || 'secret', { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, name: user.name, email: user.email, role: user.role, phone: user.phone } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Account creation is admin-only: prevents random signups against a public API.
app.post('/api/auth/register', authenticate, requireAdmin, async (req, res) => {
  try {
    const { email, password, name, role, phone } = req.body;
    if (!email || !password || !name) {
      return res.status(400).json({ error: 'email, password, and name are required' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(409).json({ error: 'A user with that email/username already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashedPassword, name, role: role || 'crew', phone });
    await user.save();
    await logAudit(req, 'user.create', 'User', user._id, { email });
    res.json({ message: 'User created', user: { id: user._id, name: user.name, email: user.email, role: user.role, phone: user.phone } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ---------- Users Routes (admin only) ----------
app.get('/api/users', authenticate, requireAdmin, async (req, res) => {
  try {
    const users = await User.find().select('-password');
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/users/:id', authenticate, requireAdmin, async (req, res) => {
  try {
    const { name, role, phone, password } = req.body;
    const update = {};
    if (name !== undefined) update.name = name;
    if (role !== undefined) update.role = role;
    if (phone !== undefined) update.phone = phone;
    if (password) {
      if (password.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters' });
      }
      update.password = await bcrypt.hash(password, 10);
    }
    const user = await User.findByIdAndUpdate(req.params.id, update, { new: true }).select('-password');
    if (!user) return res.status(404).json({ error: 'User not found' });
    await logAudit(req, 'user.update', 'User', user._id, { fields: Object.keys(update) });
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/users/:id', authenticate, requireAdmin, async (req, res) => {
  try {
    if (req.params.id === req.user.id) {
      return res.status(400).json({ error: "Can't delete your own account" });
    }
    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    await logAudit(req, 'user.delete', 'User', req.params.id, { email: user.email });
    res.json({ message: 'User deleted' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Lightweight team directory: any authenticated user can see who exists so
// they can assign crew to a schedule, even if they aren't allowed to manage
// user accounts (that stays admin-only via /api/users).
app.get('/api/team', authenticate, async (req, res) => {
  try {
    const users = await User.find().select('name role phone email');
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ---------- Customers Routes ----------
app.get('/api/customers', authenticate, async (req, res) => {
  try {
    const { search } = req.query;
    const { page, limit, skip } = getPagination(req);
    const filter = search ? { name: new RegExp(search, 'i') } : {};
    const [customers, total] = await Promise.all([
      Customer.find(filter).sort({ name: 1 }).skip(skip).limit(limit),
      Customer.countDocuments(filter)
    ]);
    res.json({ customers, total, page, limit });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/customers', authenticate, async (req, res) => {
  try {
    const { name } = req.body;
    if (!name) return res.status(400).json({ error: 'Customer name is required' });
    const customer = new Customer(req.body);
    await customer.save();
    res.json(customer);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/customers/:id', authenticate, requireManagerOrAdmin, async (req, res) => {
  try {
    const customer = await Customer.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!customer) return res.status(404).json({ error: 'Customer not found' });
    res.json(customer);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/customers/:id', authenticate, requireAdmin, async (req, res) => {
  try {
    const customer = await Customer.findByIdAndDelete(req.params.id);
    if (!customer) return res.status(404).json({ error: 'Customer not found' });
    await logAudit(req, 'customer.delete', 'Customer', req.params.id, { name: customer.name });
    res.json({ message: 'Customer deleted' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ---------- Properties Routes ----------
app.get('/api/properties', authenticate, async (req, res) => {
  try {
    const { search } = req.query;
    const { page, limit, skip } = getPagination(req);
    const filter = search
      ? { $or: [{ address: new RegExp(search, 'i') }, { city: new RegExp(search, 'i') }] }
      : {};
    const [properties, total] = await Promise.all([
      Property.find(filter).populate('customerId', 'name phone').sort({ createdAt: -1 }).skip(skip).limit(limit),
      Property.countDocuments(filter)
    ]);
    res.json({ properties, total, page, limit });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/properties', authenticate, async (req, res) => {
  try {
    const { address, city, size } = req.body;
    if (!address || !city) {
      return res.status(400).json({ error: 'address and city are required' });
    }
    if (size !== undefined && (typeof size !== 'number' || size < 0)) {
      return res.status(400).json({ error: 'size must be a positive number' });
    }
    const property = new Property(req.body);
    await property.save();
    res.json(property);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/properties/:id', authenticate, requireManagerOrAdmin, async (req, res) => {
  try {
    const property = await Property.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!property) return res.status(404).json({ error: 'Property not found' });
    res.json(property);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/properties/:id', authenticate, requireAdmin, async (req, res) => {
  try {
    const property = await Property.findByIdAndDelete(req.params.id);
    if (!property) return res.status(404).json({ error: 'Property not found' });
    if (photosEnabled) {
      for (const photo of property.photos || []) {
        cloudinary.uploader.destroy(photo.publicId).catch(() => {});
      }
    }
    await Schedule.deleteMany({ propertyId: req.params.id });
    await logAudit(req, 'property.delete', 'Property', req.params.id, { address: property.address });
    res.json({ message: 'Property deleted' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/properties/:id/photos', authenticate, upload.single('photo'), async (req, res) => {
  try {
    if (!photosEnabled) {
      return res.status(503).json({ error: 'Photo uploads are not configured on this server' });
    }
    if (!req.file) return res.status(400).json({ error: 'No photo uploaded' });
    const property = await Property.findById(req.params.id);
    if (!property) return res.status(404).json({ error: 'Property not found' });

    const result = await uploadToCloudinary(req.file.buffer);
    property.photos.push({
      url: result.secure_url,
      publicId: result.public_id,
      caption: req.body.caption || '',
      uploadedBy: req.user.email
    });
    await property.save();
    res.json(property);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/properties/:propertyId/photos/:photoId', authenticate, requireManagerOrAdmin, async (req, res) => {
  try {
    const property = await Property.findById(req.params.propertyId);
    if (!property) return res.status(404).json({ error: 'Property not found' });
    const photo = property.photos.id(req.params.photoId);
    if (!photo) return res.status(404).json({ error: 'Photo not found' });
    if (photosEnabled && photo.publicId) {
      cloudinary.uploader.destroy(photo.publicId).catch(() => {});
    }
    photo.deleteOne();
    await property.save();
    res.json(property);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ---------- Schedules Routes ----------
app.get('/api/schedules', authenticate, async (req, res) => {
  try {
    const { from, to, status } = req.query;
    const { page, limit, skip } = getPagination(req);
    const filter = {};
    if (from || to) {
      filter.date = {};
      if (from) filter.date.$gte = from;
      if (to) filter.date.$lte = to;
    }
    if (status) filter.status = status;
    const [schedules, total] = await Promise.all([
      Schedule.find(filter)
        .populate('propertyId', 'address city')
        .populate('crew', 'name email phone')
        .sort({ date: 1, time: 1 })
        .skip(skip)
        .limit(limit),
      Schedule.countDocuments(filter)
    ]);
    res.json({ schedules, total, page, limit });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

function addDays(dateStr, days) {
  const d = new Date(dateStr + 'T00:00:00Z');
  d.setUTCDate(d.getUTCDate() + days);
  return d.toISOString().slice(0, 10);
}

app.post('/api/schedules', authenticate, async (req, res) => {
  try {
    const { propertyId, date, time, recurrence } = req.body;
    if (!propertyId || !date || !time) {
      return res.status(400).json({ error: 'propertyId, date, and time are required' });
    }
    const property = await Property.findById(propertyId);
    if (!property) return res.status(400).json({ error: 'propertyId does not match any property' });

    // recurrence: { frequency: 'weekly'|'biweekly'|'monthly', count: number }
    if (recurrence && recurrence.frequency && recurrence.frequency !== 'none') {
      const stepDays = { weekly: 7, biweekly: 14, monthly: 30 }[recurrence.frequency];
      if (!stepDays) return res.status(400).json({ error: 'Invalid recurrence frequency' });
      const count = Math.min(52, Math.max(1, parseInt(recurrence.count, 10) || 8));
      const groupId = new mongoose.Types.ObjectId().toString();
      const docs = [];
      for (let i = 0; i < count; i++) {
        docs.push({
          ...req.body,
          date: addDays(date, stepDays * i),
          recurrenceGroupId: groupId
        });
      }
      const created = await Schedule.insertMany(docs.map(d => {
        const { recurrence: _r, ...rest } = d;
        return rest;
      }));
      return res.json({ created: created.length, schedules: created });
    }

    const schedule = new Schedule(req.body);
    await schedule.save();
    res.json(schedule);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/schedules/:id', authenticate, requireManagerOrAdmin, async (req, res) => {
  try {
    const schedule = await Schedule.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!schedule) return res.status(404).json({ error: 'Schedule not found' });
    res.json(schedule);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/schedules/:id', authenticate, requireAdmin, async (req, res) => {
  try {
    const schedule = await Schedule.findByIdAndDelete(req.params.id);
    if (!schedule) return res.status(404).json({ error: 'Schedule not found' });
    await logAudit(req, 'schedule.delete', 'Schedule', req.params.id, {});
    res.json({ message: 'Schedule deleted' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/schedules/:id/remind', authenticate, requireManagerOrAdmin, async (req, res) => {
  try {
    if (!process.env.TWILIO_SID || !process.env.TWILIO_AUTH_TOKEN || !process.env.TWILIO_PHONE) {
      return res.status(503).json({ error: 'Twilio is not configured on this server' });
    }
    const schedule = await Schedule.findById(req.params.id).populate('propertyId', 'address city').populate('crew', 'name phone');
    if (!schedule) return res.status(404).json({ error: 'Schedule not found' });

    const twilio = require('twilio')(process.env.TWILIO_SID, process.env.TWILIO_AUTH_TOKEN);
    const results = [];
    for (const member of schedule.crew) {
      if (!member.phone) {
        results.push({ crew: member.name, sent: false, reason: 'No phone number on file' });
        continue;
      }
      try {
        await twilio.messages.create({
          body: `LandscapeFlow reminder: you're scheduled at ${schedule.propertyId?.address || 'a job site'} on ${schedule.date} at ${schedule.time}.`,
          from: process.env.TWILIO_PHONE,
          to: member.phone
        });
        results.push({ crew: member.name, sent: true });
      } catch (smsError) {
        results.push({ crew: member.name, sent: false, reason: smsError.message });
      }
    }
    res.json({ results });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ---------- Audit Log (admin only) ----------
app.get('/api/audit-log', authenticate, requireAdmin, async (req, res) => {
  try {
    const { page, limit, skip } = getPagination(req);
    const [entries, total] = await Promise.all([
      AuditLog.find().sort({ timestamp: -1 }).skip(skip).limit(limit),
      AuditLog.countDocuments()
    ]);
    res.json({ entries, total, page, limit });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ---------- Dashboard summary ----------
app.get('/api/dashboard', authenticate, async (req, res) => {
  try {
    const today = new Date().toISOString().slice(0, 10);
    const in7 = addDays(today, 7);
    const [propertyCount, customerCount, upcomingCount, todayCount] = await Promise.all([
      Property.countDocuments(),
      Customer.countDocuments(),
      Schedule.countDocuments({ date: { $gte: today, $lte: in7 } }),
      Schedule.countDocuments({ date: today })
    ]);
    res.json({ propertyCount, customerCount, upcomingCount, todayCount });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Seed data (admin only - wipes all users, use with care)
app.post('/api/seed', authenticate, requireAdmin, async (req, res) => {
  try {
    await User.deleteMany({});
    const users = [
      { email: 'john@company.com', password: await bcrypt.hash('pass123', 10), name: 'John Doe', role: 'manager' },
      { email: 'mike@crew.com', password: await bcrypt.hash('pass123', 10), name: 'Mike Smith', role: 'crew' },
      { email: 'sarah@crew.com', password: await bcrypt.hash('pass123', 10), name: 'Sarah Johnson', role: 'crew' }
    ];
    await User.insertMany(users);
    res.json({ message: 'Database seeded' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ---------- Central error handler ----------
app.use((err, req, res, next) => {
  const errorId = Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
  console.error(`[${errorId}]`, err);
  if (err instanceof multer.MulterError || err.message === 'Only image files are allowed') {
    return res.status(400).json({ error: err.message, errorId });
  }
  res.status(500).json({ error: 'Internal server error', errorId });
});

const PORT = process.env.PORT || 5000;
if (require.main === module) {
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}

module.exports = app;
