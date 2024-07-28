import session from "express-session";
import cookieParser from "cookie-parser";
import express from "express";
import cors from "cors";
import mysql from "mysql";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import moment from "moment";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5001;

// MySQL connection
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

db.connect((err) => {
  if (err) {
    console.error("Error connecting to MySQL:", err);
    process.exit(1);
  }
  console.log("Connected to MySQL");
});

app.use(cors({ origin: "http://localhost:3000", credentials: true }));
app.use(express.json());
app.use(cookieParser());
app.use(
  session({
    secret: process.env.SESSION_SECRET || "default_secret",
    resave: false,
    saveUninitialized: true,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      httpOnly: true,
      sameSite: "strict",
      maxAge: 24 * 60 * 60 * 1000, // 1 day
    },
  })
);

// Registration route
app.post("/api/register", async (req, res) => {
  const { username, password, email, name,id } = req.body;
  if (!username || !password || !email || !name || !id) {
    return res
      .status(400)
      .json({ error: "Username, password, email, and name are required" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const sql =
      "INSERT INTO users (id,username, password, email, create_date, name) VALUES (?, ?, ?, ?, ?,?)";
    const time = moment().format("YYYY-MM-DD");
    db.query(
      sql,
      [id,username, hashedPassword, email, time, name],
      (err, result) => {
        if (err) {
          return res.status(500).json({ error: "Failed to register" });
        }
        res.json({ message: "User registered successfully" });
      }
    );
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// Login route
app.post("/api/login", async (req, res) => {
  const { username, password, email } = req.body;
  if (!username || !password || !email) {
    return res
      .status(400)
      .json({ error: "Username, password, and email are required" });
  }

  const sql = "SELECT * FROM users WHERE username = ? AND email = ?";
  db.query(sql, [username, email], async (err, result) => {
    if (err) {
      return res.status(500).json({ error: "Internal server error" });
    }
    if (result.length === 0) {
      return res.status(401).json({ error: "Username or email not found" });
    }
    const user = result[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ error: "Invalid password" });
    } else {
      req.session.user = user;
      res
        .status(200)
        .json({ message: "Logged in successfully", isLoggedIn: true });
    }
  });
});

// Check session route
app.get("/api/check-session", (req, res) => {
  if (req.session.user) {
    const user = req.session.user;
    res.status(200).json({email:user.email,username:user.username,id:user.id, isLoggedIn: true });
  } else {
    res.status(401).json({ isLoggedIn: false });
  }
});

// Logout session route
app.post("/api/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: "Failed to logout" });
    }
    res.clearCookie("connect.sid");
    res.json({ message: "Logged out successfully", isLoggedOut: true });
  });
});

// Get all notes
app.post("/notes/api", (req, res) => {
  const { username, id } = req.body;

  // Validate input
  if (!username || !id) {
    return res.status(400).json({ error: "Username and user ID are required" });
  }

  const sql = "SELECT * FROM notes WHERE username = ? AND user_id = ?";
  db.query(sql, [username, id], (err, results) => {
    if (err) {
      console.error("Error fetching notes:", err);
      return res.status(500).json({ error: "Failed to fetch notes" });
    }
    res.json(results);
  });
});
// Add note
app.post("/notes/api/add-notes", (req, res) => {
  const { title, description, username, status,user_id } = req.body;
  if (!title || !description) {
    return res
      .status(400)
      .json({ error: "Title and description are required" });
  }
  const sql =
    "INSERT INTO notes (title, description, username, status,user_id) VALUES (?, ?, ?, ?,?)";
  db.query(sql, [title, description, username, status,user_id], (err, result) => {
    if (err) {
      console.error("Error adding note:", err);
      return res.status(500).json({ error: "Failed to add note" });
    }
    res.json({ id: result.insertId, title, description });
  });
});

// Update note
app.put("/notes/api/update-notes", (req, res) => {
  const { title, description, id, username } = req.body;
  if (!title || !description || !id || !username) {
    return res
      .status(400)
      .json({ error: "Title, description, id, and username are required" });
  }
  const sql =
    "UPDATE notes SET title = ?, description = ? WHERE id = ? AND username = ?";
  db.query(sql, [title, description, id, username], (err, result) => {
    if (err) {
      return res.status(500).json({ error: "Failed to update note" });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Note not found" });
    }
    res.json({ id:result.insertId, title, description });
  });
});

// Update note status
app.put("/notes/api/update-status", (req, res) => {
  const { username, status, id } = req.body;
  if (["bin", "pin", "unpin", "archive", "other"].includes(status)) {
    // Handle status update
    const sql = "UPDATE notes SET status = ? WHERE id = ? AND username = ?";
    db.query(sql, [status, id, username], (err, result) => {
      if (err) {
        return res.status(500).json({ error: "Failed to update note status" });
      }
      res.json({ message: "Note status updated successfully" });
    });
  } else {
    res.status(400).json({ error: "Invalid status" });
  }
});

app.delete("/notes/api/delete", (req, res) => {
  const { username, id } = req.body;
  if (username && id) {
    const sql = "DELETE FROM notes WHERE id = ? AND username = ?";
    db.query(sql, [id, username], (err, result) => {
      if (err) {
        return res.status(500).json({ error: "Failed to delete note" });
      }
      if (result.affectedRows === 0) {
        return res.status(404).json({ error: "Note not found" });
      }
      res.json({ message: "Note deleted successfully" });
    });
  } else {
    res.status(400).json({ error: "Missing username or id" });
  }
});


// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
