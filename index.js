const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const app = express();

app.use(express.json({ limit: '5mb' }));

const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/levels';
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

mongoose.connect(MONGO_URI).then(() => console.log('MongoDB connected'));

// ========== Models ==========

const userSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  passwordHash: String,
  isAdmin: { type: Boolean, default: false }
});
const User = mongoose.model('User', userSchema);

const levelSchema = new mongoose.Schema({
  name: String,
  creator: String,
  data: Array,
  description: String,
  difficulty: { type: Number, default: 0 }, // 0=NA,1=Easy,2=Normal,3=Hard,4=Harder,5=Insane
  featured: { type: Boolean, default: false },
  downloads: { type: Number, default: 0 },
  likes: { type: Number, default: 0 }
});
const Level = mongoose.model('Level', levelSchema);

// ========== Middleware ==========

function authenticate(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Missing token' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(403).json({ error: 'Invalid token' });
  }
}

function requireAdmin(req, res, next) {
  if (!req.user?.isAdmin) {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

// ========== Auth Routes ==========

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const existing = await User.findOne({ username });
  if (existing) return res.status(400).json({ error: 'Username taken' });

  const passwordHash = await bcrypt.hash(password, 10);
  const user = new User({ username, passwordHash });
  await user.save();

  res.json({ message: 'Registered successfully' });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign({ username: user.username, isAdmin: user.isAdmin }, JWT_SECRET);
  res.json({ token });
});

// ========== Level Upload ==========

app.post('/levels', async (req, res) => {
  const { data, name, user, desc } = req.body;

  if (!Array.isArray(data) || !name || !user || !desc) {
    return res.status(400).json({ error: 'Missing or invalid fields' });
  }

  const level = new Level({
    name,
    creator: user,
    data,
    description: desc
  });

  await level.save();
  res.json({ message: 'Level uploaded', levelId: level._id });
});

// ========== Public Level Endpoints ==========

// Get level by ID
app.get('/levels/:id', async (req, res) => {
  const level = await Level.findById(req.params.id);
  if (!level) return res.status(404).json({ error: 'Level not found' });

  level.downloads++;
  await level.save();

  res.json(level);
});

// Like a level
app.post('/levels/:id/like', async (req, res) => {
  const level = await Level.findById(req.params.id);
  if (!level) return res.status(404).json({ error: 'Level not found' });

  level.likes++;
  await level.save();

  res.json({ message: 'Level liked' });
});

// List all levels (optionally sorted)
app.get('/levels', async (req, res) => {
  const sortField = req.query.sort;
  let sort = {};

  if (sortField === 'likes') sort.likes = -1;
  else if (sortField === 'downloads') sort.downloads = -1;
  else if (sortField === 'featured') sort.featured = -1;
  else sort._id = -1; // newest first

  const levels = await Level.find().sort(sort);
  res.json(levels);
});

// List levels by creator
app.get('/levels/by/:user', async (req, res) => {
  const levels = await Level.find({ creator: req.params.user }).sort({ _id: -1 });
  res.json(levels);
});

// Get count of levels (with optional filters)
app.get('/current', async (req, res) => {
  const filter = {};

  if (req.query.user) {
    filter.creator = req.query.user;
  }

  if (req.query.featured !== undefined) {
    filter.featured = req.query.featured === 'true';
  }

  if (req.query.difficulty !== undefined) {
    const diff = parseInt(req.query.difficulty);
    if (!isNaN(diff)) filter.difficulty = diff;
  }

  const count = await Level.countDocuments(filter);
  res.json({ count });
});

// Get stats summary, optionally filtered by user
app.get('/stats', async (req, res) => {
  const difficulties = {
    0: 'NA',
    1: 'Easy',
    2: 'Normal',
    3: 'Hard',
    4: 'Harder',
    5: 'Insane'
  };

  const filter = {};
  if (req.query.user) {
    filter.creator = req.query.user;
  }

  const stats = {};
  for (let i = 0; i <= 5; i++) {
    stats[difficulties[i]] = await Level.countDocuments({ ...filter, difficulty: i });
  }

  const featured = await Level.countDocuments({ ...filter, featured: true });
  const total = await Level.countDocuments(filter);

  res.json({
    user: req.query.user || 'all',
    total,
    featured,
    byDifficulty: stats
  });
});

// ========== Admin Routes ==========

app.post('/admin/promote', authenticate, requireAdmin, async (req, res) => {
  const { username } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.status(404).json({ error: 'User not found' });

  user.isAdmin = true;
  await user.save();
  res.json({ message: `${username} promoted to admin.` });
});

app.post('/admin/feature', authenticate, requireAdmin, async (req, res) => {
  const { levelId, featured } = req.body;
  const level = await Level.findById(levelId);
  if (!level) return res.status(404).json({ error: 'Level not found' });

  level.featured = !!featured;
  await level.save();
  res.json({ message: `Level ${featured ? 'featured' : 'unfeatured'}` });
});

app.delete('/admin/level/:id', authenticate, requireAdmin, async (req, res) => {
  const level = await Level.findByIdAndDelete(req.params.id);
  if (!level) return res.status(404).json({ error: 'Level not found' });

  res.json({ message: 'Level deleted' });
});

app.patch('/admin/level/:id', authenticate, requireAdmin, async (req, res) => {
  const allowedFields = ['difficulty', 'description'];
  const updates = {};

  for (const field of allowedFields) {
    if (req.body[field] !== undefined) updates[field] = req.body[field];
  }

  const level = await Level.findByIdAndUpdate(req.params.id, updates, { new: true });
  if (!level) return res.status(404).json({ error: 'Level not found' });

  res.json({ message: 'Level updated', level });
});

app.get('/admin/users', authenticate, requireAdmin, async (req, res) => {
  const users = await User.find();
  res.json(users);
});

app.get('/admin/levels', authenticate, requireAdmin, async (req, res) => {
  const levels = await Level.find();
  res.json(levels);
});

// ========== 404 Handler (must be last) ==========

app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// ========== Start Server ==========

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
