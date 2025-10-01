const express = require('express');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const app = express();

app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'secret-key-local';

const users = [];

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const [_,token] = authHeader && authHeader.split(' '); // Bearer TOKEN
    const queryToken = req.query.token; 

    const finalToken = token || queryToken;

    if (!finalToken) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(finalToken, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password required' });
        }

        const existingUser = users.find(user => user.username === username);
        if (existingUser) {
            return res.status(400).json({ error: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = {
            id: users.length + 1,
            username,
            password: hashedPassword
        };
        users.push(newUser);

        res.status(201).json({ message: 'User created successfully', userId: newUser.id });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password required' });
        }

        const user = users.find(user => user.username === username);
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign(
            { userId: user.id, username: user.username },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({ token, message: 'Login successful' });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});


app.get("/video", authenticateToken, (req, res) => {
    const range = req.headers.range;
    if (!range) {
        res.status(400).send("Requires Range header");
    }
    const videoPath = "video.mp4"; // todo: get video from a database or storage
    const videoSize = fs.statSync(videoPath).size;
    const CHUNK_SIZE = 10 ** 6; // 1MB
    const start = Number(range.replace(/\D/g, ""));
    const end = Math.min(start + CHUNK_SIZE, videoSize - 1);
    const contentLength = end - start + 1;
    const headers = {
        "Content-Range": `bytes ${start}-${end}/${videoSize}`,
        "Accept-Ranges": "bytes",
        "Content-Length": contentLength,
        "Content-Type": "video/mp4"
    }
    res.writeHead(206, headers);
    const videoStream = fs.createReadStream(videoPath, { start, end });
    videoStream.pipe(res);

})

app.listen(3000, () => {
    console.log("Server running on port 3000");
})

