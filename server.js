const express = require("express");
const cors = require("cors");
const fs = require("fs");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(express.json());

const USERS_FILE = "users.json";
const REQUESTS_FILE = "requests.json";

// Load users
function loadUsers() {
    try {
        return JSON.parse(fs.readFileSync(USERS_FILE));
    } catch (e) {
        return [];
    }
}

// Save users
function saveUsers(users) {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

// Load requests
function loadRequests() {
    try {
        return JSON.parse(fs.readFileSync(REQUESTS_FILE));
    } catch (e) {
        return [];
    }
}

// Save requests
function saveRequests(reqs) {
    fs.writeFileSync(REQUESTS_FILE, JSON.stringify(reqs, null, 2));
}

const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey123";


// -------------------------------------------
//  SIGNUP
// -------------------------------------------
app.post("/signup", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password)
        return res.status(400).json({ error: "Email and password required" });

    let users = loadUsers();

    if (users.find(u => u.email === email))
        return res.status(400).json({ error: "Email already registered" });

    const passwordHash = await bcrypt.hash(password, 10);

    users.push({
        email,
        passwordHash,
        createdAt: new Date().toISOString()
    });

    saveUsers(users);

    return res.json({ success: true, message: "Account created" });
});


// -------------------------------------------
//  LOGIN
// -------------------------------------------
app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    let users = loadUsers();
    const user = users.find(u => u.email === email);

    if (!user)
        return res.status(400).json({ error: "User not found" });

    const match = await bcrypt.compare(password, user.passwordHash);

    if (!match)
        return res.status(400).json({ error: "Incorrect password" });

    const token = jwt.sign({ email: user.email }, JWT_SECRET, {
        expiresIn: "7d"
    });

    return res.json({ success: true, token });
});


// -------------------------------------------
//  AUTH MIDDLEWARE
// -------------------------------------------
function auth(req, res, next) {
    const token = req.headers.authorization;

    if (!token) return res.status(401).json({ error: "Missing token" });

    try {
        const data = jwt.verify(token, JWT_SECRET);
        req.user = data;
        next();
    } catch (err) {
        res.status(401).json({ error: "Invalid token" });
    }
}


// -------------------------------------------
//  SUBMIT REQUEST (CUSTOMER TASK)
// -------------------------------------------
app.post("/submit-request", auth, (req, res) => {
    const { requestText } = req.body;

    if (!requestText)
        return res.status(400).json({ error: "Request text required" });

    let requests = loadRequests();

    requests.push({
        email: req.user.email,
        request: requestText,
        status: "pending",
        date: new Date().toISOString()
    });

    saveRequests(requests);

    return res.json({ success: true });
});


// -------------------------------------------
//  ADMIN: GET ALL REQUESTS
// -------------------------------------------
app.get("/admin/requests", (req, res) => {
    const adminKey = req.headers["x-admin-key"];

    if (adminKey !== (process.env.ADMIN_KEY || "boss123"))
        return res.status(401).json({ error: "Unauthorized" });

    const requests = loadRequests();
    res.json(requests);
});


// -------------------------------------------
//  ADMIN: UPDATE STATUS
// -------------------------------------------
app.post("/admin/update-status", (req, res) => {
    const adminKey = req.headers["x-admin-key"];

    if (adminKey !== (process.env.ADMIN_KEY || "boss123"))
        return res.status(401).json({ error: "Unauthorized" });

    const { index, status } = req.body;

    let requests = loadRequests();

    if (!requests[index])
        return res.status(400).json({ error: "Request not found" });

    requests[index].status = status;
    saveRequests(requests);

    res.json({ success: true });
});


// -------------------------------------------
//  SERVER ONLINE
// -------------------------------------------
app.get("/", (req, res) => {
    res.send("BizPilot backend is running.");
});

app.listen(3000, () => {
    console.log("BizPilot backend running on port 3000");
});
