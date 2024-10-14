const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
const users = [];  // Temporary in-memory array to store users for demo purposes
const SECRET_KEY = 'your_secret_key';  // Replace with a secure secret key

app.use(bodyParser.json());
app.use(cors());

// Signup route
app.post('/signup', async (req, res) => {
    const { username, password } = req.body;

    // Check if the user already exists
    connection.query('SELECT * FROM users WHERE username = ?', [username], async (err, results) => {
        if (err) {
            return res.status(500).json({ message: 'Database error' });
        }

        if (results.length > 0) {
            return res.status(400).json({ message: 'User already exists' });
        }

        // Hash the password and store the new user
        const hashedPassword = await bcrypt.hash(password, 10);
        connection.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], (err, results) => {
            if (err) {
                return res.status(500).json({ message: 'Error saving user' });
            }
            res.status(201).json({ message: 'User registered successfully' });
        });
    });
});


// Login route
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    // Find the user by username
    connection.query('SELECT * FROM users WHERE username = ?', [username], async (err, results) => {
        if (err) {
            return res.status(500).json({ message: 'Database error' });
        }

        if (results.length === 0) {
            return res.status(400).json({ message: 'User not found' });
        }

        const user = results[0];
        const isPasswordCorrect = await bcrypt.compare(password, user.password);

        if (!isPasswordCorrect) {
            return res.status(401).json({ message: 'Invalid password' });
        }

        const token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, { expiresIn: '1h' });
        res.json({ message: 'Login successful', token });
    });
});


// Middleware to verify token
const authenticateJWT = (req, res, next) => {
    const token = req.headers['authorization'];

    if (!token) {
        return res.status(403).json({ message: 'Token is required' });
    }

    try {
        const verified = jwt.verify(token, SECRET_KEY);
        req.user = verified;  // Attach user info to request object
        next();
    } catch (error) {
        return res.status(401).json({ message: 'Invalid token' });
    }
};

// Profile route - protected by JWT
app.get('/profile', authenticateJWT, (req, res) => {
    res.json({ message: 'Profile access granted', user: req.user });
});

// Start server
app.listen(5000, () => {
    console.log('Server running on port 5000');
});

const mysql = require('mysql2');

// Create a MySQL connection
const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',       // Replace with your MySQL username
    password: '', // Replace with your MySQL password
    database: 'auth_system'
});

connection.connect((err) => {
    if (err) {
        console.error('Error connecting to MySQL:', err);
        return;
    }
    console.log('Connected to MySQL database');
});
