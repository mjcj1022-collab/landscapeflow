const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/landscapeflow')
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => console.error('❌ MongoDB Error:', err));

// Models
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  name: String,
  role: String
});

const propertySchema = new mongoose.Schema({
  address: String,
  city: String,
  size: Number,
  manager: String,
  createdAt: { type: Date, default: Date.now }
});

const scheduleSchema = new mongoose.Schema({
  propertyId: String,
  date: String,
  time: String,
  crew: [String],
  status: String,
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Property = mongoose.model('Property', propertySchema);
const Schedule = mongoose.model('Schedule', scheduleSchema);

// Auth Routes
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET || 'secret');
    res.json({ token, user: { id: user._id, name: user.name, email: user.email, role: user.role } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name, role } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashedPassword, name, role });
    await user.save();
    res.json({ message: 'User created', user });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Properties Routes
app.get('/api/properties', async (req, res) => {
  try {
    const properties = await Property.find();
    res.json(properties);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/properties', async (req, res) => {
  try {
    const property = new Property(req.body);
    await property.save();
    res.json(property);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Schedules Routes
app.get('/api/schedules', async (req, res) => {
  try {
    const schedules = await Schedule.find();
    res.json(schedules);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/schedules', async (req, res) => {
  try {
    const schedule = new Schedule(req.body);
    await schedule.save();
    res.json(schedule);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Seed data
app.post('/api/seed', async (req, res) => {
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

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
