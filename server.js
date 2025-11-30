// server.js
require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');

// import models
const { sequelize, User, Project, Task } = require('./database/setup');
const { requireAuth } = require('./middleware/auth');
const { requireManager, requireAdmin } = require('./middleware/roles');

const app = express();
app.use(express.json());
app.use(cors());

function signToken(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '24h' });
}

// Register
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password, role = 'employee' } = req.body;
    if (!name || !email || !password) return res.status(400).json({ message: 'Name, email, and password required' });

    const existing = await User.findOne({ where: { email } });
    if (existing) return res.status(409).json({ message: 'Email already registered' });

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, passwordHash, role });
    const payload = { id: user.id, name: user.name, email: user.email, role: user.role };
    const token = signToken(payload);
    res.status(201).json({ token, user: payload });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error during registration' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Email and password required' });

    const user = await User.findOne({ where: { email }});
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) return res.status(401).json({ message: 'Invalid credentials' });

    const payload = { id: user.id, name: user.name, email: user.email, role: user.role };
    const token = signToken(payload);
    res.json({ token, user: payload });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error during login' });
  }
});

// Logout (stateless)
app.post('/api/logout', (req, res) => res.json({ message: 'Logged out (client should delete token)' }));

// Protected: get all users (admin)
app.get('/api/users', requireAuth, requireAdmin, async (req, res) => {
  try {
    const users = await User.findAll({ attributes: ['id', 'name', 'email', 'role', 'createdAt'] });
    res.json({ users });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching users' });
  }
});

// Manager routes
app.post('/api/projects', requireAuth, requireManager, async (req, res) => {
  try {
    const { title, description } = req.body;
    if (!title) return res.status(400).json({ message: 'Project title required' });
    const project = await Project.create({ title, description, createdById: req.user.id });
    res.status(201).json({ project });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error creating project' });
  }
});

app.put('/api/projects/:id', requireAuth, requireManager, async (req, res) => {
  try {
    const project = await Project.findByPk(req.params.id);
    if (!project) return res.status(404).json({ message: 'Project not found' });
    const { title, description } = req.body;
    await project.update({ title: title ?? project.title, description: description ?? project.description });
    res.json({ project });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error updating project' });
  }
});

app.post('/api/projects/:id/tasks', requireAuth, requireManager, async (req, res) => {
  try {
    const { title, description, assigneeId } = req.body;
    const project = await Project.findByPk(req.params.id);
    if (!project) return res.status(404).json({ message: 'Project not found' });

    const assignee = await User.findByPk(assigneeId);
    if (!assignee) return res.status(400).json({ message: 'Assignee not found' });

    const task = await Task.create({
      title,
      description,
      projectId: project.id,
      assigneeId: assignee.id,
      createdById: req.user.id,
      status: 'open'
    });

    res.status(201).json({ task });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error creating task' });
  }
});

app.delete('/api/tasks/:id', requireAuth, requireManager, async (req, res) => {
  try {
    const task = await Task.findByPk(req.params.id);
    if (!task) return res.status(404).json({ message: 'Task not found' });
    await task.destroy();
    res.json({ message: 'Task deleted' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error deleting task' });
  }
});

// Admin-only: delete project
app.delete('/api/projects/:id', requireAuth, requireAdmin, async (req, res) => {
  try {
    const project = await Project.findByPk(req.params.id);
    if (!project) return res.status(404).json({ message: 'Project not found' });
    await project.destroy();
    res.json({ message: 'Project deleted' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error deleting project' });
  }
});

// Employee endpoints
app.get('/api/my/tasks', requireAuth, async (req, res) => {
  try {
    const tasks = await Task.findAll({ where: { assigneeId: req.user.id }});
    res.json({ tasks });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error fetching tasks' });
  }
});

app.put('/api/tasks/:id', requireAuth, async (req, res) => {
  try {
    const task = await Task.findByPk(req.params.id);
    if (!task) return res.status(404).json({ message: 'Task not found' });

    if (req.user.role !== 'admin' && task.assigneeId !== req.user.id) {
      return res.status(403).json({ message: 'You can only modify your own tasks' });
    }

    const { title, description, status } = req.body;
    await task.update({ title: title ?? task.title, description: description ?? task.description, status: status ?? task.status });
    res.json({ task });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error updating task' });
  }
});

// Start server
const PORT = process.env.PORT || 3000;
async function start() {
  try {
    await sequelize.authenticate();
    console.log('Database connected');
    app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
  } catch (err) {
    console.error('Failed to start', err);
    process.exit(1);
  }
}
start();
