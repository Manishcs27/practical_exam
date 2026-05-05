const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const Joi = require('joi');
const rateLimit = require('express-rate-limit');

const app = express();
app.use(express.json());

const users = [];
const products = [];
const orders = [];
const refreshStore = new Map();

const ACCESS_SECRET = process.env.ACCESS_SECRET || 'access-secret-demo';
const REFRESH_SECRET = process.env.REFRESH_SECRET || 'refresh-secret-demo';


const apiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 200 });
app.use(apiLimiter);

(async function seed() {
    const pw = await bcrypt.hash('adminpass', 8);
    users.push({ id: uuidv4(), name: 'Admin', email: 'admin@example.com', passwordHash: pw, role: 'admin', createdAt: new Date().toISOString() });
})();

const registerSchema = Joi.object({ name: Joi.string().min(2).required(), email: Joi.string().email().required(), password: Joi.string().min(6).required() });
const loginSchema = Joi.object({ email: Joi.string().email().required(), password: Joi.string().required() });
const productSchema = Joi.object({ name: Joi.string().required(), price: Joi.number().positive().required(), stock: Joi.number().integer().min(0).required(), category: Joi.string().optional().allow('') });
const orderSchema = Joi.object({ products: Joi.array().items(Joi.object({ productId: Joi.string().required(), quantity: Joi.number().integer().min(1).required() })).min(1).required() });


function generateAccessToken(user) {
    return jwt.sign({ id: user.id, role: user.role }, ACCESS_SECRET, { expiresIn: '15m' });
}

function generateRefreshToken(user) {
    return jwt.sign({ id: user.id }, REFRESH_SECRET, { expiresIn: '7d' });
}

function storeRefreshToken(userId, token) {
    const set = refreshStore.get(userId) || new Set();
    set.add(token);
    refreshStore.set(userId, set);
}

function revokeRefreshToken(userId, token) {
    const set = refreshStore.get(userId);
    if (set) {
        set.delete(token);
    }
}
function calculateTotal(orderId) {
    const order = orders.find(o => o.id === orderId);
    if (!order) return 0;
    let total = 0;
    for (const item of order.products) {
        const p = products.find(x => x.id === item.productId);
        if (p) total += p.price * item.quantity;
    }
    return total;
}


function authMiddleware(req, res, next) {
    const auth = req.headers.authorization;
    if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Missing token' });
    const token = auth.slice(7);
    try {
        const payload = jwt.verify(token, ACCESS_SECRET);
        req.user = payload;
        return next();
    } catch (err) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
}

function requireRole(role) {
    return (req, res, next) => {
        if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
        if (req.user.role !== role) return res.status(403).json({ error: 'Forbidden' });
        next();
    };
}


app.post('/register', async (req, res) => {
    const { error, value } = registerSchema.validate(req.body);
    if (error) return res.status(400).json({ error: error.message });
    const exists = users.find(u => u.email === value.email.toLowerCase());
    if (exists) return res.status(409).json({ error: 'Email already registered' });
    const hash = await bcrypt.hash(value.password, 8);
    const user = { id: uuidv4(), name: value.name, email: value.email.toLowerCase(), passwordHash: hash, role: 'user', createdAt: new Date().toISOString() };
    users.push(user);
    res.status(201).json({ id: user.id, name: user.name, email: user.email, role: user.role });
});

app.post('/login', async (req, res) => {
    const { error, value } = loginSchema.validate(req.body);
    if (error) return res.status(400).json({ error: error.message });
    const user = users.find(u => u.email === value.email.toLowerCase());
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(value.password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    storeRefreshToken(user.id, refreshToken);
    res.json({ accessToken, refreshToken });
});

app.post('/token', (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(400).json({ error: 'Missing refreshToken' });
    try {
        const payload = jwt.verify(refreshToken, REFRESH_SECRET);
        const userId = payload.id;
        const set = refreshStore.get(userId);
        if (!set || !set.has(refreshToken)) return res.status(403).json({ error: 'Refresh token revoked' });
        const user = users.find(u => u.id === userId);
        if (!user) return res.status(401).json({ error: 'Unknown user' });
        const newAccess = generateAccessToken(user);
        res.json({ accessToken: newAccess });
    } catch (err) {
        return res.status(403).json({ error: 'Invalid refresh token' });
    }
});

app.post('/logout', authMiddleware, (req, res) => {
    const { refreshToken } = req.body;
    if (refreshToken) revokeRefreshToken(req.user.id, refreshToken);
    res.json({ ok: true });
});

app.get('/products', (req, res) => res.json(products));

app.post('/products', authMiddleware, requireRole('admin'), (req, res) => {
    const { error, value } = productSchema.validate(req.body);
    if (error) return res.status(400).json({ error: error.message });
    const p = { id: uuidv4(), name: value.name, price: value.price, stock: value.stock, category: value.category || '', createdAt: new Date().toISOString() };
    products.push(p);
    res.status(201).json(p);
});

app.put('/products/:id', authMiddleware, requireRole('admin'), (req, res) => {
    const { id } = req.params;
    const prod = products.find(p => p.id === id);
    if (!prod) return res.status(404).json({ error: 'Product not found' });
    const { error, value } = productSchema.validate(req.body);
    if (error) return res.status(400).json({ error: error.message });
    prod.name = value.name; prod.price = value.price; prod.stock = value.stock; prod.category = value.category || '';
    res.json(prod);
});

app.delete('/products/:id', authMiddleware, requireRole('admin'), (req, res) => {
    const { id } = req.params;
    const idx = products.findIndex(p => p.id === id);
    if (idx === -1) return res.status(404).json({ error: 'Product not found' });
    products.splice(idx, 1);
    res.status(204).end();
});


app.post('/orders', authMiddleware, async (req, res) => {
    const { error, value } = orderSchema.validate(req.body);
    if (error) return res.status(400).json({ error: error.message });
 
    for (const item of value.products) {
        const p = products.find(x => x.id === item.productId);
        if (!p) return res.status(400).json({ error: `Product ${item.productId} not found` });
        if (p.stock < item.quantity) return res.status(400).json({ error: `Insufficient stock for ${p.name}` });
    }

    const order = { id: uuidv4(), userId: req.user.id, products: value.products.map(it => ({ productId: it.productId, quantity: it.quantity })), totalAmount: 0, status: 'placed', createdAt: new Date().toISOString() };
    orders.push(order);

    for (const item of order.products) {
        const p = products.find(x => x.id === item.productId);
        p.stock -= item.quantity;
    }

    order.totalAmount = calculateTotal(order.id);
    res.status(201).json(order);
});

app.get('/orders', authMiddleware, (req, res) => {
    if (req.user.role === 'admin') return res.json(orders);
    const my = orders.filter(o => o.userId === req.user.id);
    res.json(my);
});

app.get('/orders/:id/total', authMiddleware, (req, res) => {
    const { id } = req.params;
    const order = orders.find(o => o.id === id);
    if (!order) return res.status(404).json({ error: 'Order not found' });
    if (req.user.role !== 'admin' && order.userId !== req.user.id) return res.status(403).json({ error: 'Forbidden' });
    const total = calculateTotal(id);
    res.json({ orderId: id, total });
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

