const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const app = express();

app.use(express.json({ limit: '5mb' }));

const JWT_SECRET = process.env.JWT_SECRET || 'j1o2i1o2k02mlw';

// ===== In-memory "DB" =====

const users = []; // { username, passwordHash, isAdmin }
const levels = []; // { id, name, creator, data, description, difficulty, featured, downloads, likes }

let levelIdCounter = 1;

// ===== Helpers =====

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
  if (!req.user?.isAdmin) return res.status(403).json({ error: 'Admin access required' });
  next();
}

// ===== Auth =====

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing username or password' });

  if (users.find(u => u.username === username)) {
    return res.status(400).json({ error: 'Username taken' });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  users.push({ username, passwordHash, isAdmin: false });

  res.json({ message: 'Registered successfully' });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

  const token = jwt.sign({ username: user.username, isAdmin: user.isAdmin }, JWT_SECRET);
  res.json({ token });
});

// ===== Level Upload =====

app.post('/levels', (req, res) => {
  const { data, name, user, desc } = req.body;
  if (!Array.isArray(data) || !name || !user || !desc) {
    return res.status(400).json({ error: 'Missing or invalid fields' });
  }

  const level = {
    id: levelIdCounter++,
    name,
    creator: user,
    data,
    description: desc,
    difficulty: 0, // default NA
    featured: false,
    downloads: 0,
    likes: 0
  };

  levels.push(level);
  res.json({ message: 'Level uploaded', levelId: level.id });
});

// ===== Public Level Endpoints =====

// Get level by ID
app.get('/levels/:id', (req, res) => {
  const level = levels.find(l => l.id === +req.params.id);
  if (!level) return res.status(404).json({ error: 'Level not found' });

  level.downloads++;
  res.json(level);
});

// Like a level
app.post('/levels/:id/like', (req, res) => {
  const level = levels.find(l => l.id === +req.params.id);
  if (!level) return res.status(404).json({ error: 'Level not found' });

  level.likes++;
  res.json({ message: 'Level liked' });
});

// List all levels with optional sorting
app.get('/levels', (req, res) => {
  const sortField = req.query.sort;
  let sortedLevels = [...levels];

  if (sortField === 'likes') sortedLevels.sort((a,b) => b.likes - a.likes);
  else if (sortField === 'downloads') sortedLevels.sort((a,b) => b.downloads - a.downloads);
  else if (sortField === 'featured') sortedLevels.sort((a,b) => (b.featured === a.featured)?0:(b.featured?1:-1));
  else sortedLevels.sort((a,b) => b.id - a.id);

  res.json(sortedLevels);
});

// List levels by creator
app.get('/levels/by/:user', (req, res) => {
  const userLevels = levels.filter(l => l.creator === req.params.user).sort((a,b) => b.id - a.id);
  res.json(userLevels);
});

// Count levels with optional filters
app.get('/current', (req, res) => {
  let filtered = [...levels];

  if (req.query.user) filtered = filtered.filter(l => l.creator === req.query.user);
  if (req.query.featured !== undefined) filtered = filtered.filter(l => l.featured === (req.query.featured === 'true'));
  if (req.query.difficulty !== undefined) filtered = filtered.filter(l => l.difficulty === +req.query.difficulty);

  res.json({ count: filtered.length });
});

// Stats summary with optional user filter
app.get('/stats', (req, res) => {
  const difficulties = {
    0: 'NA',
    1: 'Easy',
    2: 'Normal',
    3: 'Hard',
    4: 'Harder',
    5: 'Insane'
  };

  let filtered = levels;
  if (req.query.user) filtered = filtered.filter(l => l.creator === req.query.user);

  const stats = {};
  for (let i = 0; i <= 5; i++) {
    stats[difficulties[i]] = filtered.filter(l => l.difficulty === i).length;
  }

  const featuredCount = filtered.filter(l => l.featured).length;
  const total = filtered.length;

  res.json({
    user: req.query.user || 'all',
    total,
    featured: featuredCount,
    byDifficulty: stats
  });
});

// ===== Admin Routes =====

app.post('/admin/promote', authenticate, requireAdmin, (req, res) => {
  const { username } = req.body;
  const user = users.find(u => u.username === username);
  if (!user) return res.status(404).json({ error: 'User not found' });

  user.isAdmin = true;
  res.json({ message: `${username} promoted to admin.` });
});

app.post('/admin/feature', authenticate, requireAdmin, (req, res) => {
  const { levelId, featured } = req.body;
  const level = levels.find(l => l.id === +levelId);
  if (!level) return res.status(404).json({ error: 'Level not found' });

  level.featured = !!featured;
  res.json({ message: `Level ${featured ? 'featured' : 'unfeatured'}` });
});

app.delete('/admin/level/:id', authenticate, requireAdmin, (req, res) => {
  const index = levels.findIndex(l => l.id === +req.params.id);
  if (index === -1) return res.status(404).json({ error: 'Level not found' });

  levels.splice(index, 1);
  res.json({ message: 'Level deleted' });
});

app.patch('/admin/level/:id', authenticate, requireAdmin, (req, res) => {
  const level = levels.find(l => l.id === +req.params.id);
  if (!level) return res.status(404).json({ error: 'Level not found' });

  const allowedFields = ['difficulty', 'description'];
  for (const field of allowedFields) {
    if (req.body[field] !== undefined) level[field] = req.body[field];
  }

  res.json({ message: 'Level updated', level });
});

app.get('/admin/users', authenticate, requireAdmin, (req, res) => {
  res.json(users);
});

app.get('/admin/levels', authenticate, requireAdmin, (req, res) => {
  res.json(levels);
});

// ===== 404 Handler =====

app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// ===== Start Server =====

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
