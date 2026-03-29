const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const cors = require('cors');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'arcade-games-secret-key-2024';

// ============ EMAIL CONFIGURATION ============
// Configure Gmail SMTP transporter
// NOTE: For production, use App Password (not your regular Gmail password)
// To get App Password: https://myaccount.google.com/apppasswords
const emailConfig = {
    service: 'gmail',
    auth: {
        user: 'bogbetsite@gmail.com',
        pass: 'yggp cfak uhbv gtly'
    }
};

const transporter = nodemailer.createTransport(emailConfig);

const sendVerificationEmail = (email, verificationCode) => {
    const verificationUrl = `http://localhost:${PORT}/verify.html?code=${verificationCode}`;
    
    const mailOptions = {
        from: '"Bogbet" <noreply@bogbet.com>',
        to: email,
        subject: 'Verify your Bogbet account',
        html: `
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body { font-family: Arial, sans-serif; background: #0a0e17; color: #fff; padding: 20px; }
                    .container { max-width: 500px; margin: 0 auto; background: #121a2d; border-radius: 16px; padding: 30px; text-align: center; }
                    .logo { font-size: 40px; margin-bottom: 20px; }
                    h1 { color: #00d4ff; margin-bottom: 20px; }
                    p { color: #8b9dc3; margin-bottom: 20px; line-height: 1.6; }
                    .code { background: #0a0e17; padding: 15px; border-radius: 8px; font-size: 24px; color: #00ff88; letter-spacing: 5px; margin: 20px 0; }
                    .button { display: inline-block; background: linear-gradient(135deg, #00d4ff, #0099cc); color: #0a0e17; padding: 15px 30px; border-radius: 12px; text-decoration: none; font-weight: bold; margin: 10px 0; }
                    .footer { margin-top: 30px; color: #8b9dc3; font-size: 12px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="logo">🎮</div>
                    <h1>Verify Your Email</h1>
                    <p>Welcome to Bogbet! Please verify your email address to start playing.</p>
                    <p>Your verification code:</p>
                    <div class="code">${verificationCode}</div>
                    <p>Or click the button below:</p>
                    <a href="${verificationUrl}" class="button">Verify Email</a>
                    <div class="footer">
                        <p>If you didn't create an account, please ignore this email.</p>
                        <p>© 2024 Bogbet</p>
                    </div>
                </div>
            </body>
            </html>
        `
    };

    return transporter.sendMail(mailOptions);
};

// ============ MIDDLEWARE ============
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Database setup
const db = new sqlite3.Database(path.join(__dirname, 'arcade.db'), (err) => {
    if (err) console.error('Database connection error:', err.message);
    else console.log('Connected to SQLite database');
});

// Initialize database tables
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            balance REAL DEFAULT 10,
            level INTEGER DEFAULT 1,
            xp INTEGER DEFAULT 0,
            unlocked_games TEXT DEFAULT '{"plinko":false,"blackjack":false}',
            unlocked_jobs TEXT DEFAULT '[]',
            verified INTEGER DEFAULT 0,
            verification_code TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS verification_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            code TEXT NOT NULL,
            expires_at DATETIME NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS game_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            game_type TEXT NOT NULL,
            bet_amount REAL,
            result_amount REAL,
            won INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    `);
});

// Authentication middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Authentication required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

// ============ AUTH ROUTES ============

// Register - sends verification email
app.post('/api/register', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password required' });
    }

    if (password.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({ error: 'Invalid email format' });
    }

    // Check if user exists
    db.get('SELECT id, verified FROM users WHERE email = ?', [email], (err, row) => {
        if (row) {
            if (row.verified === 0) {
                // User exists but not verified - resend verification
                generateAndSendVerification(row.id, email);
                return res.json({ 
                    message: 'Verification email resent. Please check your inbox.',
                    needsVerification: true 
                });
            }
            return res.status(400).json({ error: 'Email already registered and verified' });
        }

        // Hash password and create user
        bcrypt.hash(password, 10, (err, hash) => {
            if (err) {
                return res.status(500).json({ error: 'Error hashing password' });
            }

            // Generate verification code
            const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
            const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

            db.run(
                'INSERT INTO users (email, password, balance, verification_code) VALUES (?, ?, ?, ?)',
                [email, hash, 10, verificationCode],
                function(err) {
                    if (err) {
                        return res.status(500).json({ error: 'Error creating user' });
                    }

                    const userId = this.lastID;

                    // Store verification token
                    db.run(
                        'INSERT INTO verification_tokens (user_id, code, expires_at) VALUES (?, ?, ?)',
                        [userId, verificationCode, expiresAt.toISOString()]
                    );

                    // Send verification email (will fail if Gmail not configured, but that's okay)
                    sendVerificationEmail(email, verificationCode).then(() => {
                        console.log(`✅ Verification email sent to ${email}`);
                    }).catch(err => {
                        console.log(`📧 Email not configured - showing code on screen for ${email}`);
                    });

                    // Always show code in response for verification (works without email)
                    console.log(`🔐 Verification code for ${email}: ${verificationCode}`);

                    res.json({
                        message: 'Registration successful! Please check your email to verify your account.',
                        needsVerification: true,
                        verificationCode: verificationCode, // Include code for display
                        user: {
                            id: userId,
                            email,
                            balance: 10,
                            verified: false,
                            unlockedGames: { plinko: false, blackjack: false }
                        }
                    });
                }
            );
        });
    });
});

// Helper function to generate and resend verification
function generateAndSendVerification(userId, email) {
    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

    db.run('UPDATE users SET verification_code = ? WHERE id = ?', [verificationCode, userId]);
    db.run('INSERT INTO verification_tokens (user_id, code, expires_at) VALUES (?, ?, ?)', 
        [userId, verificationCode, expiresAt.toISOString()]);

    sendVerificationEmail(email, verificationCode).then(() => {
        console.log(`Verification email resent to ${email}`);
    }).catch(err => {
        console.error('Error sending email:', err.message);
    });
}

// Verify email endpoint
app.post('/api/verify-email', (req, res) => {
    const { code, email } = req.body;

    if (!code || !email) {
        return res.status(400).json({ error: 'Verification code and email required' });
    }

    db.get('SELECT id, verification_code, verified FROM users WHERE email = ?', [email], (err, user) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (!user) return res.status(404).json({ error: 'User not found' });
        if (user.verified === 1) return res.status(400).json({ error: 'Email already verified' });

        if (user.verification_code === code) {
            db.run('UPDATE users SET verified = 1, verification_code = NULL WHERE id = ?', [user.id]);
            
            // Clean up verification tokens
            db.run('DELETE FROM verification_tokens WHERE user_id = ?', [user.id]);

            // Generate login token
            const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

            res.json({
                message: 'Email verified successfully!',
                token,
                user: {
                    id: user.id,
                    email: user.email,
                    balance: 10,
                    level: user.level || 1,
                    xp: user.xp || 0,
                    verified: true,
                    unlockedGames: { plinko: false, blackjack: false }
                }
            });
        } else {
            res.status(400).json({ error: 'Invalid verification code' });
        }
    });
});

// Resend verification email
app.post('/api/resend-verification', (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ error: 'Email required' });
    }

    db.get('SELECT id, verified FROM users WHERE email = ?', [email], (err, user) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (!user) return res.status(404).json({ error: 'User not found' });
        if (user.verified === 1) return res.status(400).json({ error: 'Email already verified' });

        generateAndSendVerification(user.id, email);
        
        res.json({ message: 'Verification email resent. Please check your inbox.' });
    });
});

// Login
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password required' });
    }

    db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }

        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        // Check if email is verified
        if (user.verified === 0) {
            return res.status(403).json({ 
                error: 'Please verify your email first',
                needsVerification: true,
                email: email
            });
        }

        bcrypt.compare(password, user.password, (err, match) => {
            if (err) {
                return res.status(500).json({ error: 'Error checking password' });
            }

            if (!match) {
                return res.status(401).json({ error: 'Invalid email or password' });
            }

            const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

            res.json({
                message: 'Login successful',
                token,
                user: {
                    id: user.id,
                    email: user.email,
                    balance: user.balance,
                    level: user.level || 1,
                    xp: user.xp || 0,
                    unlockedGames: JSON.parse(user.unlocked_games),
                    unlockedJobs: JSON.parse(user.unlocked_jobs || '[]'),
                    ownedItems: JSON.parse(user.owned_items || '[]'),
                    equippedSkin: user.equipped_skin || 'skin_default',
                    equippedTrail: user.equipped_trail || 'trail_none',
                    verified: true
                }
            });
        });
    });
});

// Get user info
app.get('/api/user', authenticateToken, (req, res) => {
    db.get('SELECT id, email, balance, level, xp, unlocked_games, unlocked_jobs, verified, created_at, owned_items, equipped_skin, equipped_trail FROM users WHERE id = ?',
        [req.user.id],
        (err, user) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }

            if (!user) {
                return res.status(404).json({ error: 'User not found' });
            }

            res.json({
                id: user.id,
                email: user.email,
                balance: user.balance,
                level: user.level || 1,
                xp: user.xp || 0,
                verified: user.verified === 1,
                unlockedGames: JSON.parse(user.unlocked_games),
                unlockedJobs: JSON.parse(user.unlocked_jobs || '[]'),
                ownedItems: JSON.parse(user.owned_items || '[]'),
                equippedSkin: user.equipped_skin || 'skin_default',
                equippedTrail: user.equipped_trail || 'trail_none',
                createdAt: user.created_at
            });
        }
    );
});

// Update balance
app.put('/api/balance', authenticateToken, (req, res) => {
    const { amount, operation, gameType, betAmount, won } = req.body;

    // Check if user is verified
    db.get('SELECT verified FROM users WHERE id = ?', [req.user.id], (err, user) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (user.verified === 0) return res.status(403).json({ error: 'Please verify your email first' });

        if (operation === 'set') {
            db.run('UPDATE users SET balance = ? WHERE id = ?', [amount, req.user.id], (err) => {
                if (err) return res.status(500).json({ error: 'Error updating balance' });
                
                if (gameType) {
                    db.run(
                        'INSERT INTO game_sessions (user_id, game_type, bet_amount, result_amount, won) VALUES (?, ?, ?, ?, ?)',
                        [req.user.id, gameType, betAmount, amount, won ? 1 : 0]
                    );
                }

                res.json({ balance: amount });
            });
        } else if (operation === 'add' || operation === 'subtract') {
            const actualAmount = operation === 'add' ? amount : -amount;
            
            db.get('SELECT balance FROM users WHERE id = ?', [req.user.id], (err, row) => {
                if (err) return res.status(500).json({ error: 'Database error' });
                
                const newBalance = Math.max(0, row.balance + actualAmount);
                
                db.run('UPDATE users SET balance = ? WHERE id = ?', [newBalance, req.user.id], (err) => {
                    if (err) return res.status(500).json({ error: 'Error updating balance' });

                    if (gameType) {
                        db.run(
                            'INSERT INTO game_sessions (user_id, game_type, bet_amount, result_amount, won) VALUES (?, ?, ?, ?, ?)',
                            [req.user.id, gameType, betAmount, won ? betAmount * (won - 1) : 0, won ? 1 : 0]
                        );
                    }

                    res.json({ balance: newBalance });
                });
            });
        } else {
            res.status(400).json({ error: 'Invalid operation' });
        }
    });
});

// Unlock game
app.put('/api/unlock-game', authenticateToken, (req, res) => {
    const { game } = req.body;
    const validGames = ['plinko', 'blackjack'];
    
    if (!validGames.includes(game)) {
        return res.status(400).json({ error: 'Invalid game' });
    }

    const costs = { plinko: 100, blackjack: 20000 };

    db.get('SELECT balance, unlocked_games, verified FROM users WHERE id = ?', [req.user.id], (err, row) => {
        if (err) return res.status(500).json({ error: 'Database error' });

        if (row.verified === 0) {
            return res.status(403).json({ error: 'Please verify your email first' });
        }

        const unlockedGames = JSON.parse(row.unlocked_games);
        
        if (unlockedGames[game]) {
            return res.status(400).json({ error: 'Game already unlocked' });
        }

        if (row.balance < costs[game]) {
            return res.status(400).json({ error: 'Insufficient balance' });
        }

        const newBalance = row.balance - costs[game];
        unlockedGames[game] = true;

        db.run(
            'UPDATE users SET balance = ?, unlocked_games = ? WHERE id = ?',
            [newBalance, JSON.stringify(unlockedGames), req.user.id],
            (err) => {
                if (err) return res.status(500).json({ error: 'Error unlocking game' });

                res.json({
                    message: `${game} unlocked!`,
                    balance: newBalance,
                    unlockedGames
                });
            }
        );
    });
});

// Add XP from job completion
app.post('/api/add-xp', authenticateToken, (req, res) => {
    const { xp } = req.body;
    
    if (!xp || xp <= 0) {
        return res.status(400).json({ error: 'Invalid XP amount' });
    }

    db.get('SELECT level, xp FROM users WHERE id = ?', [req.user.id], (err, user) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        
        let newXp = (user.xp || 0) + xp;
        let newLevel = user.level || 1;
        
        // XP needed for each level (increases with level)
        const xpForLevel = (level) => level * 100;
        
        // Check for level up
        while (newXp >= xpForLevel(newLevel)) {
            newXp -= xpForLevel(newLevel);
            newLevel++;
        }
        
        db.run('UPDATE users SET xp = ?, level = ? WHERE id = ?', [newXp, newLevel, req.user.id], (err) => {
            if (err) return res.status(500).json({ error: 'Error updating XP' });
            
            res.json({
                xp: newXp,
                level: newLevel,
                xpForNextLevel: xpForLevel(newLevel)
            });
        });
    });
});

// Get game history
app.get('/api/history', authenticateToken, (req, res) => {
    const limit = parseInt(req.query.limit) || 20;
    
    db.all(
        'SELECT * FROM game_sessions WHERE user_id = ? ORDER BY created_at DESC LIMIT ?',
        [req.user.id, limit],
        (err, rows) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            res.json(rows);
        }
    );
});

// Logout
app.post('/api/logout', authenticateToken, (req, res) => {
    res.json({ message: 'Logged out successfully' });
});

// Save owned items
app.put('/api/owned-items', authenticateToken, (req, res) => {
    const { ownedItems } = req.body;
    
    if (!ownedItems || !Array.isArray(ownedItems)) {
        return res.status(400).json({ error: 'Invalid owned items' });
    }
    
    db.run('UPDATE users SET owned_items = ? WHERE id = ?', [JSON.stringify(ownedItems), req.user.id], (err) => {
        if (err) return res.status(500).json({ error: 'Error saving owned items' });
        res.json({ success: true, ownedItems });
    });
});

// Save equipped items
app.put('/api/equipped-items', authenticateToken, (req, res) => {
    const { currentSkin, currentTrail } = req.body;
    
    db.run('UPDATE users SET equipped_skin = ?, equipped_trail = ? WHERE id = ?', 
        [currentSkin || 'skin_default', currentTrail || 'trail_none', req.user.id], 
        (err) => {
            if (err) return res.status(500).json({ error: 'Error saving equipped items' });
            res.json({ success: true, currentSkin, currentTrail });
        }
    );
});

// Serve the main HTML file
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log('========================================');
    console.log('To enable email verification:');
    console.log('1. Set GMAIL_USER environment variable');
    console.log('2. Use Gmail App Password (not regular password)');
    console.log('   Get it at: https://myaccount.google.com/apppasswords');
    console.log('========================================');
});
