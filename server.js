import express from 'express';
import cors from 'cors';
import fs from 'fs';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

const app = express();

app.use(cors());
app.use(express.json());

const DB_FILE = './db.json';
const USERS_FILE = './users.json';
const REVIEWS_FILE = './reviews.json';

// JWT secret from environment variable
const JWT_SECRET = process.env.JWT_SECRET || 'development_secret';

// ==================== INITIALIZE FILES ====================

if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(
        DB_FILE,
        JSON.stringify({ products: [], orders: [] }, null, 2)
    );
}

if (!fs.existsSync(USERS_FILE)) {
    fs.writeFileSync(
        USERS_FILE,
        JSON.stringify({ users: [] }, null, 2)
    );
}

if (!fs.existsSync(REVIEWS_FILE)) {
    fs.writeFileSync(
        REVIEWS_FILE,
        JSON.stringify({ reviews: [] }, null, 2)
    );
}

// ==================== DATABASE HELPERS ====================

const readDB = () =>
    JSON.parse(fs.readFileSync(DB_FILE));

const writeDB = (data) =>
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));

const readUsers = () =>
    JSON.parse(fs.readFileSync(USERS_FILE));

const writeUsers = (data) =>
    fs.writeFileSync(USERS_FILE, JSON.stringify(data, null, 2));

const readReviews = () =>
    JSON.parse(fs.readFileSync(REVIEWS_FILE));

const writeReviews = (data) =>
    fs.writeFileSync(REVIEWS_FILE, JSON.stringify(data, null, 2));

// ==================== AUTH MIDDLEWARE ====================

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access denied' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }

        req.user = user;
        next();
    });
};

// ==================== ADMIN MIDDLEWARE ====================

const isAdmin = (req, res, next) => {
    const users = readUsers();

    const user = users.users.find(
        (u) => u.id === req.user.id
    );

    if (!user || !user.isAdmin) {
        return res.status(403).json({
            error: 'Admin access required'
        });
    }

    next();
};

// ==================== AUTH ROUTES ====================

// Register
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({
            error: 'Username and password required'
        });
    }

    if (password.length < 6) {
        return res.status(400).json({
            error: 'Password must be at least 6 characters'
        });
    }

    const users = readUsers();

    if (users.users.find((u) => u.username === username)) {
        return res.status(400).json({
            error: 'Username already exists'
        });
    }

    // First registered user becomes admin
    const isAdmin = users.users.length === 0;

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = {
        id: Date.now(),
        username,
        password: hashedPassword,
        isAdmin
    };

    users.users.push(newUser);

    writeUsers(users);

    res.status(201).json({
        message: 'User registered successfully',
        isAdmin
    });
});

// Login
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    const users = readUsers();

    const user = users.users.find(
        (u) => u.username === username
    );

    if (!user) {
        return res.status(400).json({
            error: 'Invalid credentials'
        });
    }

    const valid = await bcrypt.compare(
        password,
        user.password
    );

    if (!valid) {
        return res.status(400).json({
            error: 'Invalid credentials'
        });
    }

    const token = jwt.sign(
        {
            id: user.id,
            username: user.username,
            isAdmin: user.isAdmin
        },
        JWT_SECRET,
        { expiresIn: '1h' }
    );

    res.json({
        token,
        username: user.username,
        isAdmin: user.isAdmin
    });
});

// ==================== ADMIN USER ROUTES ====================

app.get(
    '/api/admin/users',
    authenticateToken,
    isAdmin,
    (req, res) => {
        const users = readUsers();

        const safeUsers = users.users.map((u) => ({
            id: u.id,
            username: u.username,
            isAdmin: u.isAdmin
        }));

        res.json(safeUsers);
    }
);

app.put(
    '/api/admin/users/:id',
    authenticateToken,
    isAdmin,
    (req, res) => {
        const { id } = req.params;
        const { isAdmin } = req.body;

        const users = readUsers();

        const userIndex = users.users.findIndex(
            (u) => u.id === parseInt(id)
        );

        if (userIndex === -1) {
            return res.status(404).json({
                error: 'User not found'
            });
        }

        users.users[userIndex].isAdmin = isAdmin;

        writeUsers(users);

        res.json({
            message: 'User updated'
        });
    }
);

app.delete(
    '/api/admin/users/:id',
    authenticateToken,
    isAdmin,
    (req, res) => {
        const { id } = req.params;

        const users = readUsers();

        const filtered = users.users.filter(
            (u) => u.id !== parseInt(id)
        );

        if (filtered.length === users.users.length) {
            return res.status(404).json({
                error: 'User not found'
            });
        }

        users.users = filtered;

        writeUsers(users);

        res.json({
            message: 'User deleted'
        });
    }
);

// ==================== ADMIN ORDER ROUTES ====================

app.get(
    '/api/admin/orders',
    authenticateToken,
    isAdmin,
    (req, res) => {
        const db = readDB();

        res.json(db.orders);
    }
);

// ==================== ADMIN PRODUCT ROUTES ====================

app.post(
    '/api/admin/products',
    authenticateToken,
    isAdmin,
    (req, res) => {
        const db = readDB();

        const newProduct = {
            id: Date.now(),
            ...req.body
        };

        db.products.push(newProduct);

        writeDB(db);

        res.status(201).json(newProduct);
    }
);

app.put(
    '/api/admin/products/:id',
    authenticateToken,
    isAdmin,
    (req, res) => {
        const { id } = req.params;

        const db = readDB();

        const productIndex = db.products.findIndex(
            (p) => p.id === parseInt(id)
        );

        if (productIndex === -1) {
            return res.status(404).json({
                error: 'Product not found'
            });
        }

        db.products[productIndex] = {
            ...db.products[productIndex],
            ...req.body
        };

        writeDB(db);

        res.json(db.products[productIndex]);
    }
);

app.delete(
    '/api/admin/products/:id',
    authenticateToken,
    isAdmin,
    (req, res) => {
        const { id } = req.params;

        const db = readDB();

        const filtered = db.products.filter(
            (p) => p.id !== parseInt(id)
        );

        if (filtered.length === db.products.length) {
            return res.status(404).json({
                error: 'Product not found'
            });
        }

        db.products = filtered;

        writeDB(db);

        res.json({
            message: 'Product deleted'
        });
    }
);

// ==================== USER PROFILE ROUTES ====================

app.get(
    '/api/profile',
    authenticateToken,
    (req, res) => {
        const users = readUsers();

        const user = users.users.find(
            (u) => u.id === req.user.id
        );

        if (!user) {
            return res.status(404).json({
                error: 'User not found'
            });
        }

        res.json({
            username: user.username,
            name: user.name || '',
            address: user.address || ''
        });
    }
);

app.put(
    '/api/profile',
    authenticateToken,
    async (req, res) => {
        const {
            name,
            address,
            currentPassword,
            newPassword
        } = req.body;

        const users = readUsers();

        const userIndex = users.users.findIndex(
            (u) => u.id === req.user.id
        );

        if (userIndex === -1) {
            return res.status(404).json({
                error: 'User not found'
            });
        }

        const user = users.users[userIndex];

        if (currentPassword && newPassword) {
            const valid = await bcrypt.compare(
                currentPassword,
                user.password
            );

            if (!valid) {
                return res.status(400).json({
                    error: 'Current password is incorrect'
                });
            }

            user.password = await bcrypt.hash(
                newPassword,
                10
            );
        }

        if (name) {
            user.name = name;
        }

        if (address) {
            user.address = address;
        }

        writeUsers(users);

        res.json({
            message: 'Profile updated'
        });
    }
);

// ==================== PUBLIC ROUTES ====================

app.get('/', (req, res) => {
    res.send('Online Store API (Mock Database)');
});

// Products
app.get('/api/products', (req, res) => {
    const db = readDB();

    res.json(db.products);
});

// Orders
app.get('/api/orders', (req, res) => {
    const db = readDB();

    res.json(db.orders);
});

app.post('/api/orders', (req, res) => {
    console.log('POST /api/orders received');

    const db = readDB();

    const newOrder = {
        id: Date.now(),
        customer: req.body.customer,
        items: req.body.items,
        total: req.body.total,
        date: new Date().toISOString()
    };

    db.orders.push(newOrder);

    writeDB(db);

    res.status(201).json(newOrder);
});

// ==================== REVIEW ROUTES ====================

app.get('/api/reviews/:productId', (req, res) => {
    const { productId } = req.params;

    const reviews = readReviews();

    const productReviews = reviews.reviews.filter(
        (r) => r.productId === parseInt(productId)
    );

    res.json(productReviews);
});

app.post(
    '/api/reviews',
    authenticateToken,
    (req, res) => {
        const {
            productId,
            rating,
            comment
        } = req.body;

        if (
            !productId ||
            !rating ||
            rating < 1 ||
            rating > 5
        ) {
            return res.status(400).json({
                error: 'Invalid rating or productId'
            });
        }

        const reviews = readReviews();

        const newReview = {
            id: Date.now(),
            productId,
            username: req.user.username,
            rating,
            comment: comment || '',
            date: new Date().toISOString()
        };

        reviews.reviews.push(newReview);

        writeReviews(reviews);

        res.status(201).json(newReview);
    }
);

// ==================== SERVER ====================

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
