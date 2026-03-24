require("dotenv").config();
const express = require("express");
const cors = require("cors");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const { S3Client, PutObjectCommand } = require("@aws-sdk/client-s3");
const { v4: uuidv4 } = require("uuid");


const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// multer memory storage for direct S3 upload (limit 20MB)
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 20 * 1024 * 1024 } });

const SALT_ROUNDS = 10;
const ALLOWED_TYPES = ["UNIVERSITY", "ORGANIZER"];

/* ================= DATABASE ================= */
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: { rejectUnauthorized: false },
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  connectTimeout: 15000 // Give it 15 seconds to connect
});

db.connect(err => {
  if (err) console.error("❌ DB Error:", err);
  else console.log("✅ MySQL Connected");
});

/* ================= AWS S3 ================= */
const s3 = new S3Client({
  region: process.env.AWS_REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
  }
});

/* ================= JWT MIDDLEWARE ================= */
function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ message: "Missing Authorization header" });
  }

  const token = authHeader.split(" ")[1];
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (err) {
    return res.status(403).json({ message: "Invalid token" });
  }
}

/* ================= REGISTER ORGANIZER ================= */
app.post("/reg/organizers", async (req, res) => {
  const {
    firstname,
    lastname,
    organizer_name,
    email,
    phone,
    username,
    password,
    organizer_type
  } = req.body;

  if (!firstname || !lastname || !organizer_name || !email || !username || !password) {
    return res.status(400).json({ message: "Missing required fields" });
  }

  if (!ALLOWED_TYPES.includes(organizer_type)) {
    return res.status(400).json({ message: "Invalid organizer_type" });
  }

  if (password.length < 8) {
    return res.status(400).json({ message: "Password must be at least 8 characters" });
  }

  try {
    const sql = `
      INSERT INTO organizer
      (firstname, lastname, organizer_name, email, phone, username, password, organizer_type)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `;

    db.query(
      sql,
      [
        firstname,
        lastname,
        organizer_name,
        email,
        phone || null,
        username,
        password,
        organizer_type
      ],
      (err, result) => {
        if (err) {
          if (err.code === "ER_DUP_ENTRY") {
            return res.status(400).json({ message: "Email or Username already exists" });
          }
          return res.status(500).json(err);
        }

        res.status(201).json({
          message: "Organizer created",
          organizer_id: result.insertId
        });
      }
    );
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

/* ================= LOGIN ================= */
app.post("/login/organizers", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Missing username or password" });
  }

  const sql = `SELECT * FROM organizer WHERE username = ? LIMIT 1`;
  db.query(sql, [username], async (err, rows) => {
    if (err) return res.status(500).json(err);
    if (!rows.length) {
      return res.status(401).json({ message: "Invalid username or password" });
    }

    const user = rows[0];
    
    const token = jwt.sign(
      {
        organizer_id: user.organizer_id,
        organizer_type: user.organizer_type
      },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    if (password !== user.password) {
      return res.status(401).json({ message: "Invalid username or password" });
    }else if (password === user.password) {
      // Passwords match
      
    delete user.password;

    res.json({
      message: "Login success",
      token,
      user
    });
    }
  });
});

/* ================= CREATE EVENT ================= */
app.post("/post/event", verifyToken, (req, res) => {
  const {
    organizer_id,
    organizer_name,
    title,
    description,
    location,
    open_date,
    close_date,
    image_url,
    contact1,
    contact2,
    status
  } = req.body;

  if (!organizer_id || !organizer_name || !title || !description || !location || !open_date || !close_date || !contact1) {
    return res.status(400).json({ message: "Missing required fields" });
  }

  if (new Date(close_date) <= new Date(open_date)) {
    return res.status(400).json({ message: "Close date must be after open date" });
  }

  /* ===== generate ACTxxxxxx ===== */
  const getLastIdSQL = `
    SELECT activity_id 
    FROM event 
    ORDER BY activity_id DESC 
    LIMIT 1
  `;

  db.query(getLastIdSQL, (err, rows) => {
    if (err) return res.status(500).json(err);

    let newActivityId = "ACT000001";
    if (rows.length) {
      const lastId = rows[0].activity_id;
      const number = parseInt(lastId.replace("ACT", ""));
      newActivityId = `ACT${String(number + 1).padStart(6, "0")}`;
    }

    /* ===== insert event ===== */
    if (!["เปิดรับ", "ใกล้เต็ม"].includes(status)) {
      return res.status(400).json({ message: "Invalid status. Must be 'เปิดรับ' or 'ใกล้เต็ม'" });
    }

    const insertSQL = `
      INSERT INTO event (
      activity_id,
      organizer_id,
      organizer_name,
      title,
      description,
      location,
      open_date,
      close_date,
      image_url,
      contact1,
      contact2,
      status,
      created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
    `;

    db.query(
      insertSQL,
      [
        newActivityId,
        organizer_id,
        organizer_name,
        title,
        description,
        location,
        open_date,
        close_date,
        image_url || null,
        contact1,
        contact2 || null,
        status
      ],
      (err) => {
        if (err) {
          console.error('❌ Insert event error:', err);
          return res.status(500).json({ message: 'Failed to insert event', error: err });
        }

        res.status(201).json({
          message: "Event created successfully",
          activity_id: newActivityId,
          image_url
        });
      }
    );
  });
});


/* ================= S3 PRESIGNED URL ================= */
app.post("/s3/presign", verifyToken, async (req, res) => {
  const { fileName, fileType } = req.body;
  const allowedTypes = ["image/jpeg", "image/png", "image/webp"];

  if (!allowedTypes.includes(fileType)) {
    return res.status(400).json({ message: "Invalid file type" });
  }

  const key = `daily-life-event-photo/${Date.now()}-${fileName}`;

  const command = new PutObjectCommand({
    Bucket: process.env.AWS_S3_BUCKET_NAME,
    Key: key,
    ContentType: fileType
  });

  const uploadUrl = await getSignedUrl(s3, command, { expiresIn: 3600 });

  res.json({
    uploadUrl,
    imageUrl: `https://${process.env.AWS_S3_BUCKET_NAME}.s3.amazonaws.com/${key}`
  });
});


// Direct upload endpoint: accepts multipart/form-data with field name 'image'
app.post('/s3/upload', verifyToken, upload.single('image'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ message: 'No file uploaded' });

    const file = req.file;
    const allowed = ['image/jpeg', 'image/png', 'image/webp'];
    if (!allowed.includes(file.mimetype)) {
      return res.status(400).json({ message: 'Invalid file type' });
    }

    const key = `daily-life-event-photo/${Date.now()}-${uuidv4()}-${file.originalname.replace(/\s+/g,'_')}`;

    const command = new PutObjectCommand({
      Bucket: process.env.AWS_S3_BUCKET_NAME,
      Key: key,
      Body: file.buffer,
      ContentType: file.mimetype
    });

    await s3.send(command);

    const imageUrl = `https://${process.env.AWS_S3_BUCKET_NAME}.s3.amazonaws.com/${key}`;
    return res.json({ imageUrl });
  } catch (err) {
    console.error('S3 upload error:', err);
    return res.status(500).json({ message: 'Failed to upload file', error: err });
  }
});

// Multer error handler (catch file size and other multer errors)
app.use((err, req, res, next) => {
  if (err && err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ message: 'File too large. Max size is 20MB.' });
    }
    return res.status(400).json({ message: err.message });
  }
  next(err);
});


app.get("/getall/event/:id", (req, res) => {
  const { id } = req.params;
  const sql = "SELECT * FROM event WHERE organizer_id = ?";
  db.query(sql, [id], (err, results) => {
    if (err) {
      console.error("Error fetching event:", err);
      return res.status(500).json({ message: "Failed to fetch event" });
    }
    if (results.length === 0) {
      return res.status(404).json({ message: "Event not found" });
    }
    res.json(results);
  });
});

/* ================= START SERVER ================= */
app.listen(process.env.PORT || 5000, () => {
  console.log(`🚀 Server running on port ${process.env.PORT || 5000}`);
});
