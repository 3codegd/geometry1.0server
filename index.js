const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const app = express();

// Parse JSON bodies (application/json)
app.use(express.json({ limit: '5mb' }));
// Parse raw text bodies (text/plain)
app.use(express.text({ type: 'text/plain', limit: '5mb' }));

// Middleware: if Content-Type is text/plain, parse text as JSON
app.use((req, res, next) => {
  if (req.is('text/plain') && req.body) {
    try {
      req.body = JSON.parse(req.body);
    } catch {
      return res.status(400).json({ error: 'Invalid JSON in text/plain body' });
    }
  }
  next();
});

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// In-memory "database"
const users = [];
const levels = [];

let levelIdCounter = 1;

// --- Helpers ---
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Missing token' });
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(403).json({ error: 'Invalid token' });
  }
}

function requireAdmin(req, res, next) {
  if (!req.user?.isAdmin) return res.status(403).json({ error: 'Admin access required' });
  next();
}

// --- Auth ---

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing username or password' });
  if (users.find(u => u.username === username)) return res.status(400).json({ error: 'Username taken' });

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

// --- Level Upload ---

app.post('/levels', (req, res) => {
  console.log('Body received:', req.body);
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
    difficulty: 0, // NA by default
    featured: false,
    downloads: 0,
    likes: 0,
  };

  levels.push(level);
  res.json({ message: 'Level uploaded', levelId: level.id });
});

// --- Get level by ID (increments downloads) ---

app.get('/levels/:id', (req, res) => {
  const id = +req.params.id;
  const level = levels.find(l => l.id === id);
  if (!level) return res.status(404).json({ error: 'Level not found' });

  level.downloads++;
  res.json(level);
});

// --- Like a level ---

app.post('/levels/:id/like', (req, res) => {
  const id = +req.params.id;
  const level = levels.find(l => l.id === id);
  if (!level) return res.status(404).json({ error: 'Level not found' });

  level.likes++;
  res.json({ message: 'Level liked' });
});

// --- List all levels with optional sorting ---

app.get('/levels', (req, res) => {
  const sort = req.query.sort;
  let sorted = [...levels];

  if (sort === 'likes') sorted.sort((a,b) => b.likes - a.likes);
  else if (sort === 'downloads') sorted.sort((a,b) => b.downloads - a.downloads);
  else if (sort === 'featured') sorted.sort((a,b) => (b.featured === a.featured) ? 0 : (b.featured ? 1 : -1));
  else sorted.sort((a,b) => b.id - a.id);

  res.json(sorted);
});

// --- List levels by creator ---

app.get('/levels/by/:user', (req, res) => {
  const user = req.params.user;
  const userLevels = levels.filter(l => l.creator === user).sort((a,b) => b.id - a.id);
  res.json(userLevels);
});

// --- Count levels with filters (current) ---

app.get('/current', (req, res) => {
  let filtered = [...levels];
  if (req.query.user) filtered = filtered.filter(l => l.creator === req.query.user);
  if (req.query.featured !== undefined) filtered = filtered.filter(l => l.featured === (req.query.featured === 'true'));
  if (req.query.difficulty !== undefined) filtered = filtered.filter(l => l.difficulty === +req.query.difficulty);

  res.json({ count: filtered.length });
});

// --- Stats summary with difficulty breakdown ---

app.get('/stats', (req, res) => {
  const difficulties = {
    0: 'NA',
    1: 'Easy',
    2: 'Normal',
    3: 'Hard',
    4: 'Harder',
    5: 'Insane',
  };

  let filtered = [...levels];
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
    byDifficulty: stats,
  });
});

// --- ADMIN ROUTES ---

app.post('/admin/promote', authenticate, requireAdmin, (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'Missing username' });
  const user = users.find(u => u.username === username);
  if (!user) return res.status(404).json({ error: 'User not found' });

  user.isAdmin = true;
  res.json({ message: `${username} promoted to admin.` });
});

app.post('/admin/feature', authenticate, requireAdmin, (req, res) => {
  const { levelId, featured } = req.body;
  if (typeof levelId !== 'number' || typeof featured !== 'boolean') {
    return res.status(400).json({ error: 'Missing or invalid levelId/featured' });
  }
  const level = levels.find(l => l.id === levelId);
  if (!level) return res.status(404).json({ error: 'Level not found' });

  level.featured = featured;
  res.json({ message: `Level ${featured ? 'featured' : 'unfeatured'}` });
});

app.delete('/admin/level/:id', authenticate, requireAdmin, (req, res) => {
  const id = +req.params.id;
  const index = levels.findIndex(l => l.id === id);
  if (index === -1) return res.status(404).json({ error: 'Level not found' });

  levels.splice(index, 1);
  res.json({ message: 'Level deleted' });
});

app.patch('/admin/level/:id', authenticate, requireAdmin, (req, res) => {
  const id = +req.params.id;
  const level = levels.find(l => l.id === id);
  if (!level) return res.status(404).json({ error: 'Level not found' });

  const allowedFields = ['difficulty', 'description'];
  for (const f of allowedFields) {
    if (req.body[f] !== undefined) level[f] = req.body[f];
  }

  res.json({ message: 'Level updated', level });
});

app.get('/admin/users', authenticate, requireAdmin, (req, res) => {
  // Don't send password hashes
  const safeUsers = users.map(u => ({
    username: u.username,
    isAdmin: u.isAdmin,
  }));
  res.json(safeUsers);
});

app.get('/admin/levels', authenticate, requireAdmin, (req, res) => {
  res.json(levels);
});
app.get('/search/:query', (req, res) => {
  const query = req.params.query.trim();

  if (!query) return res.status(400).json({ error: 'Empty search query' });

  // If query is a number, search by id
  if (/^\d+$/.test(query)) {
    const id = Number(query);
    const level = levels.find(l => l.id === id);
    if (!level) return res.status(404).json({ error: 'Level not found' });
    return res.json([level]);
  }

  // Else, search by title/name starting with query (case-insensitive)
  const lowerQuery = query.toLowerCase();
  const matched = levels.filter(l => l.name.toLowerCase().startsWith(lowerQuery));

  res.json(matched);
});

// --- 404 handler ---

app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// --- Error handler ---

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Internal Server Error', message: err.message });
});

// --- Start server ---

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
