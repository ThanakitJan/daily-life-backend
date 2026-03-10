require("dotenv").config();
const express = require("express");
const cors = require("cors");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const { S3Client, PutObjectCommand } = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");
const { v4: uuidv4 } = require("uuid");
const os = require('os');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ================= MULTER =================
const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, path.join(os.tmpdir(), 'uploads')),
    filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname.replace(/\s+/g,'_')}`)
  }),
  limits: { fileSize: 100 * 1024 * 1024 } // 100MB
});

const SALT_ROUNDS = 10;
const ALLOWED_TYPES = ["UNIVERSITY", "ORGANIZER"];

// ========== DATABASE CONNECTION ==========
const db = mysql.createPool({
  host: process.env.DB_HOST || "daily-life-demo-1.cfwiseyse6is.ap-southeast-2.rds.amazonaws.com",
  user: process.env.DB_USER || "admin",
  password: process.env.DB_PASSWORD || "awd486S5!qq",
  database: process.env.DB_NAME || "Daily_Life_DB",
  port: process.env.DB_PORT || "3306",
  ssl: { rejectUnauthorized: false },
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Quick health-check
db.getConnection((err, connection) => {
  if (err) {
    console.log("❌ Database Error:", err);
  } else {
    console.log("✅ MySQL Pool Connected!");
    connection.release();
  }
});

// ========== AWS S3 ==========
const s3 = new S3Client({
  region: process.env.AWS_REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
  }
});

// ========== JWT MIDDLEWARE ==========
function verifyToken(req, res, next) {
  const auth = req.headers['authorization'] || req.headers['Authorization'];
  console.log('Authorization header:', auth);
  
  if (!auth) {
    return res.status(401).json({ message: 'Invalid token - no Authorization header' });
  }

  const parts = auth.trim().split(/\s+/);
  console.log('Authorization parts:', parts);
  
  if (parts.length !== 2 || !/^Bearer$/i.test(parts[0])) {
    return res.status(401).json({ message: 'Invalid token - bad format' });
  }

  const token = parts[1];

  // Debug logging
  console.log('JWT secret present:', !!process.env.JWT_SECRET, 'len=', process.env.JWT_SECRET ? process.env.JWT_SECRET.length : 0);
  console.log('JWT public key present:', !!process.env.JWT_PUBLIC_KEY);

  // Try to decode header to inspect alg
  let header = null;
  try {
    const headerB64 = token.split('.')[0];
    header = JSON.parse(Buffer.from(headerB64, 'base64').toString('utf8'));
    console.log('Token header:', header);
  } catch (e) {
    console.warn('Could not decode token header:', e && e.message);
  }

  const alg = header && header.alg ? header.alg : null;

  if (alg === 'RS256') {
    const pubKey = process.env.JWT_PUBLIC_KEY;
    if (!pubKey) {
      console.error('RS256 token but JWT_PUBLIC_KEY not set');
      return res.status(401).json({ message: 'Invalid token - missing public key for RS256' });
    }
    jwt.verify(token, pubKey, { algorithms: ['RS256'] }, (err, decoded) => {
      if (err) {
        console.error('JWT verify error (RS256):', err && err.message);
        return res.status(401).json({ message: 'Invalid token - verify failed', error: err && err.message });
      }
      console.log('JWT decoded (RS256):', decoded);
      req.user = decoded;
      next();
    });
    return;
  }

  // Default: HS256
  const secret = process.env.JWT_SECRET || "change_this_secret";
  jwt.verify(token, secret, { algorithms: ['HS256'] }, (err, decoded) => {
    if (err) {
      console.error('JWT verify error (HS256):', err && err.message);
      return res.status(401).json({ message: 'Invalid token - verify failed', error: err && err.message });
    }
    console.log('JWT decoded (HS256):', decoded);
    req.user = decoded;
    next();
  });
}

// ================= S3 UPLOAD HELPER =================
const uploadToS3 = async (file, folder) => {
  const allowed = ['image/jpeg', 'image/png', 'image/webp'];
  if (!allowed.includes(file.mimetype)) throw new Error('Invalid file type');

  const key = `${folder}/${Date.now()}-${uuidv4()}-${path.basename(file.path)}`;
  const fileStream = fs.createReadStream(file.path);

  const command = new PutObjectCommand({
    Bucket: process.env.AWS_S3_BUCKET_NAME,
    Key: key,
    Body: fileStream,
    ContentType: file.mimetype
  });

  await s3.send(command);

  // ลบไฟล์ชั่วคราว
  fs.unlink(file.path, () => {});

  return `https://${process.env.AWS_S3_BUCKET_NAME}.s3.amazonaws.com/${key}`;
};


// ========== AUTHENTICATION ENDPOINTS ==========

// Login (User)
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const sql = "SELECT * FROM users WHERE username = ?";

  db.query(sql, [username], (err, results) => {
    if (err) {
      console.log("❌ DB ERROR:", err);
      return res.status(500).json({ success: false, message: "Login Failed", error: err });
    }

    const user = results[0];
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    if (password === user.password) {
      const payload = { id: user.id, username: user.username };
      const secret = process.env.JWT_SECRET || "change_this_secret";
      const token = jwt.sign(payload, secret, { expiresIn: "7d" });

      return res.json({
        success: true,
        message: "Login Success",
        user: { id: user.id, username: user.username, firstname: user.firstname, lastname: user.lastname, profile: user.profile_image || null },
        token: `${token}`
      });
    } else {
      return res.status(401).json({ success: false, message: "Invalid password" });
    }
  });
});

// Register (User)
app.post("/api/register", (req, res) => {
  const { firstname, lastname, email, phone, username, password } = req.body;
  const sql = `
    INSERT INTO users 
    (firstname, lastname, email, phone, username, password) 
    VALUES (?, ?, ?, ?, ?, ?)
  `;

  db.query(sql, [firstname, lastname, email, phone, username, password], (err, result) => {
    if (err) {
      console.error("=======================================");
      console.error(`[${new Date().toISOString()}] FATAL DB INSERT ERROR`);
      console.error("SQL Query:", sql.trim());
      console.error("Parameters:", [firstname, lastname, email, phone, username, password]);
      console.error("Error Details:", err);
      console.error("=======================================");

      return res.status(500).json({
        success: false,
        message: "Register Failed: Internal Server Error",
        error_code: err.code || "UNKNOWN_DB_ERROR"
      });
    }

    return res.json({ success: true, message: "Register Success", id: result.insertId });
  });
});

// Register Organizer
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
      [firstname, lastname, organizer_name, email, phone || null, username, password, organizer_type],
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

// Login Organizer
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
    
    if (password !== user.password) {
      return res.status(401).json({ message: "Invalid username or password" });
    }

    const token = jwt.sign(
      {
        organizer_id: user.organizer_id,
        organizer_type: user.organizer_type
      },
      process.env.JWT_SECRET || "change_this_secret",
      { expiresIn: "7d" }
    );

    delete user.password;

    res.json({
      message: "Login success",
      token,
      user
    });
  });
});

// ========== USER ENDPOINTS ==========

// Get all users
app.get("/user/get-all", (req, res) => {
  const sql = "SELECT * FROM users";

  db.query(sql, (err, results) => {
    if (err) {
      console.log("❌ DB ERROR:", err);
      return res.status(500).json({ success: false, message: "Failed to fetch users", error: err });
    }
    return res.json({ success: true, data: results });
  });
});

// Get user by ID
app.get("/user/get/:id", (req, res) => {
  const { id } = req.params;
  const sql = "SELECT * FROM users WHERE id = ?";

  db.query(sql, [id], (err, results) => {
    if (err) {
      console.log("❌ DB ERROR:", err);
      return res.status(500).json({ success: false, message: "Search Failed", error: err });
    }

    if (results.length === 0) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    return res.json({ success: true, data: results[0] });
  });
});

// Update user profile
app.put("/user/update/:id", (req, res) => {
  const { id } = req.params;
  const { firstname, lastname, email, phone, username, password, profile_image } = req.body;

  if (!firstname && !lastname && !email && !phone && !username && !password && !profile_image) {
    return res.status(400).json({
      success: false,
      message: "No fields provided for update"
    });
  }

  let sql = "UPDATE users SET ";
  const fields = [];
  const params = [];

  if (firstname) { fields.push("firstname = ?"); params.push(firstname); }
  if (lastname) { fields.push("lastname = ?"); params.push(lastname); }
  if (email) { fields.push("email = ?"); params.push(email); }
  if (phone) { fields.push("phone = ?"); params.push(phone); }
  if (username) { fields.push("username = ?"); params.push(username); }
  if (password) { fields.push("password = ?"); params.push(password); }
  if (profile_image) { fields.push("profile_image = ?"); params.push(profile_image); }

  sql += fields.join(", ") + " WHERE id = ?";
  params.push(id);

  console.log("UPDATE PROFILE:", sql, params);

  db.query(sql, params, (err, result) => {
    if (err) {
      console.error(`[${new Date().toISOString()}] DB UPDATE ERROR:`, err);
      return res.status(500).json({
        success: false,
        message: "Update Failed: Internal Server Error",
        error_code: err.code || "UNKNOWN_DB_ERROR"
      });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({
        success: false,
        message: "User Not Found"
      });
    }

    return res.json({
      success: true,
      message: "Profile Updated Successfully"
    });
  });
});

// Admin update user profile
app.put("/admin/user/:id", (req, res) => {
  const { id } = req.params;
  const { firstname, lastname, email, phone, username, password, profile_image } = req.body;

  if (!firstname && !lastname && !email && !phone && !username && !password && !profile_image) {
    return res.status(400).json({
      success: false,
      message: "No fields provided for update"
    });
  }

  let sql = "UPDATE users SET ";
  const fields = [];
  const params = [];

  if (password && password.trim() !== '') {
    fields.push("password = ?");
    params.push(password);
  }

  if (firstname) { fields.push("firstname = ?"); params.push(firstname); }
  if (lastname) { fields.push("lastname = ?"); params.push(lastname); }
  if (email) { fields.push("email = ?"); params.push(email); }
  if (phone) { fields.push("phone = ?"); params.push(phone); }
  if (username) { fields.push("username = ?"); params.push(username); }
  if (profile_image) { fields.push("profile_image = ?"); params.push(profile_image); }

  if (fields.length === 0) {
    return res.status(400).json({
      success: false,
      message: "No fields provided for update"
    });
  }

  sql += fields.join(", ") + " WHERE id = ?";
  params.push(id);

  console.log("ADMIN UPDATE:", sql, params);

  db.query(sql, params, (err, result) => {
    if (err) {
      console.error(`[${new Date().toISOString()}] DB UPDATE ERROR:`, err);

      let errorMessage = "Database Error";
      let statusCode = 500;
      if (err.code === 'ER_DUP_ENTRY') {
        errorMessage = "Email or Username already exists.";
        statusCode = 409;
      }

      return res.status(statusCode).json({
        success: false,
        message: errorMessage,
        error_code: err.code
      });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: "User Not Found" });
    }

    return res.json({ success: true, message: "Profile Updated Successfully" });
  });
});

// Delete user
app.delete("/user/delete/:id", (req, res) => {
  const { id } = req.params;
  const sql = "DELETE FROM users WHERE id = ?";

  db.query(sql, [id], (err, results) => {
    if (err) {
      console.log("❌ DB ERROR:", err);
      return res.status(500).json({ success: false, error: "Database error during deletion" });
    }

    if (results.affectedRows === 0) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    return res.json({ success: true, message: "User Deleted Successfully", id });
  });
});

// ========== UNIVERSITY ENDPOINTS ==========

// Get all universities
app.get("/university/get-all", (req, res) => {
  const sql = "SELECT * FROM un_data";

  db.query(sql, (err, results) => {
    if (err) {
      console.log("❌ DB ERROR:", err);
      return res.status(500).json({ success: false, message: "Search Failed", error: err });
    }
    return res.json({ success: true, data: results });
  });
});

// Search universities
app.post("/university/search", (req, res) => {
  const { university_th, university_en, shortName, faculty, major, province } = req.body;

  let sql = "SELECT * FROM un_data WHERE 1=1";
  const params = [];

  if (university_th && university_th.trim()) {
    sql += " AND university_th LIKE ?";
    params.push(`%${university_th}%`);
  }

  if (university_en && university_en.trim()) {
    sql += " AND university_en LIKE ?";
    params.push(`%${university_en}%`);
  }

  if (shortName && shortName.trim()) {
    sql += " AND university_shortname LIKE ?";
    params.push(`%${shortName}%`);
  }

  if (province && province.trim()) {
    sql += " AND province LIKE ?";
    params.push(`%${province}%`);
  }

  if (faculty && faculty.trim()) {
    sql += " AND JSON_SEARCH(faculties, 'one', ?) IS NOT NULL";
    params.push(faculty);
  }

  if (major && major.trim()) {
    sql += " AND JSON_SEARCH(majors, 'one', ?) IS NOT NULL";
    params.push(major);
  }

  console.log("SEARCH QUERY:", sql, params);

  db.query(sql, params, (err, results) => {
    if (err) {
      console.log("❌ DB ERROR:", err);
      return res.status(500).json({
        success: false,
        message: "Search Failed",
        error: err.message
      });
    }

    if (results.length === 0) {
      return res.status(404).json({
        success: false,
        message: "No universities found",
        data: []
      });
    }

    return res.json({
      success: true,
      message: `Found ${results.length} result(s)`,
      data: results
    });
  });
});

// Get university by ID
app.get("/university/view/:id", (req, res) => {
  const { id } = req.params;
  const sql = "SELECT * FROM un_data WHERE id = ?";

  db.query(sql, [id], (err, results) => {
    if (err) {
      console.error("❌ DB ERROR:", err);
      return res.status(500).json({ success: false, message: "Database Error", error: err });
    }

    if (results.length === 0) {
      return res.status(404).json({ success: false, message: "University not found" });
    }

    return res.json({ success: true, data: results[0] });
  });
});

// Add new university
app.post("/university/add", (req, res) => {
  const {
    university_th,
    university_en,
    university_shortname,
    university_type,
    province,
    website,
    logo,
    campuses,
    faculties,
    majors
  } = req.body;

  if (!university_th || !university_en || !university_shortname) {
    return res.status(400).json({
      success: false,
      message: "Missing required fields"
    });
  }

  const processField = (data, type) => {
    if (!data || !Array.isArray(data) || data.length === 0) return null;

    const processed = data
      .filter(item => {
        const nameField = type === "campuses" ? "campus_name" : type === "faculties" ? "faculty_name" : "major_name";
        return item[nameField] && item[nameField].trim();
      })
      .map((item, index) => {
        const nameField = type === "campuses" ? "campus_name" : type === "faculties" ? "faculty_name" : "major_name";
        return {
          id: index + 1,
          [nameField]: item[nameField].trim()
        };
      });

    return processed.length > 0 ? JSON.stringify(processed) : null;
  };

  const sql = `
    INSERT INTO un_data (
      university_th,
      university_en,
      university_shortname,
      university_type,
      province,
      website,
      logo,
      campuses,
      faculties,
      majors
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;

  const params = [
    university_th,
    university_en,
    university_shortname,
    university_type || null,
    province || null,
    website || null,
    logo || null,
    processField(campuses, "campuses"),
    processField(faculties, "faculties"),
    processField(majors, "majors")
  ];

  db.query(sql, params, (err, result) => {
    if (err) {
      console.error("❌ UNIVERSITY INSERT ERROR:", err);
      return res.status(500).json({
        success: false,
        message: err.code === "ER_DUP_ENTRY" ? "University short name already exists" : "Insert failed",
        error: err.message
      });
    }

    return res.json({
      success: true,
      message: "University added successfully",
      id: result.insertId
    });
  });
});

// Update university
app.put("/university/edit/:id", (req, res) => {
  const { id } = req.params;
  const body = req.body;

  console.log("📌 Incoming Edit Request:", body);

  const allowedFields = [
    "university_th",
    "university_en",
    "university_shortname",
    "university_type",
    "province",
    "website",
    "logo",
    "campuses",
    "faculties",
    "majors"
  ];

  let sqlParts = [];
  let params = [];

  allowedFields.forEach(field => {
    if (body.hasOwnProperty(field)) {
      let value = body[field];

      if (typeof value === "object" && value !== null) {
        value = JSON.stringify(value);
      }

      sqlParts.push(`${field} = ?`);
      params.push(value);
    }
  });

  if (sqlParts.length === 0) {
    return res.status(400).json({
      success: false,
      message: "No valid fields provided for update"
    });
  }

  const sql = `UPDATE un_data SET ${sqlParts.join(", ")} WHERE id = ?`;
  params.push(id);

  console.log("📝 SQL:", sql);
  console.log("🧩 Params:", params);

  db.query(sql, params, (err, result) => {
    if (err) {
      console.error("❌ DB UPDATE ERROR:", err);
      return res.status(500).json({
        success: false,
        message: "Update Failed",
        error: err,
      });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({
        success: false,
        message: "University not found",
      });
    }

    return res.json({
      success: true,
      message: "University Updated Successfully",
    });
  });
});

// Delete university
app.delete("/university/delete/:id", (req, res) => {
  const { id } = req.params;
  const sql = "DELETE FROM un_data WHERE id = ?";

  db.query(sql, [id], (err, results) => {
    if (err) {
      console.log("❌ DB ERROR:", err);
      return res.status(500).json({ success: false, error: "Database error during deletion" });
    }

    if (results.affectedRows === 0) {
      return res.status(404).json({ success: false, message: "University not found" });
    }

    return res.json({ success: true, message: "University Deleted Successfully", id });
  });
});

// ========== EVENT ENDPOINTS ==========

// Get all events (grouped by organizer)
app.get("/event/get", (req, res) => {
  const sql = `
    SELECT 
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
      status
    FROM event
    ORDER BY organizer_id, open_date
  `;

  db.query(sql, (err, results) => {
    if (err) {
      console.error("❌ Error fetching events:", err);
      return res.status(500).json({
        success: false,
        message: "Failed to fetch events"
      });
    }

    const organizersMap = {};

    results.forEach(row => {
      if (!organizersMap[row.organizer_id]) {
        organizersMap[row.organizer_id] = {
          organizer_id: row.organizer_id,
          organizer_name: row.organizer_name,
          activities: []
        };
      }

      organizersMap[row.organizer_id].activities.push({
        activity_id: row.activity_id,
        title: row.title,
        description: row.description,
        location: row.location,
        open_date: row.open_date,
        close_date: row.close_date,
        image_url: row.image_url,
        contact1: row.contact1,
        contact2: row.contact2,
        status: row.status
      });
    });

    const data = Object.values(organizersMap);

    res.json({
      success: true,
      data
    });
  });
});

// Get event by ID
app.get("/event/get/:id", (req, res) => {
  const { id } = req.params;

  if (!id) {
    return res.status(400).json({
      success: false,
      message: "Event ID is required"
    });
  }

  const sql = "SELECT * FROM event WHERE activity_id = ?";

  db.query(sql, [id], (err, results) => {
    if (err) {
      console.log("❌ DB ERROR:", err);
      return res.status(500).json({
        success: false,
        message: "Search Failed",
        error: err
      });
    }

    if (results.length === 0) {
      return res.status(404).json({
        success: false,
        message: "Event not found"
      });
    }

    return res.json({
      success: true,
      data: results[0]
    });
  });
});

// Get events by organizer ID
app.get("/event/organizer/:organizerId", (req, res) => {
  const { organizerId } = req.params;

  if (!organizerId) {
    return res.status(400).json({
      success: false,
      message: "Organizer ID is required"
    });
  }

  const sql = "SELECT * FROM event WHERE organizer_id = ?";

  db.query(sql, [organizerId], (err, results) => {
    if (err) {
      console.log("❌ DB ERROR:", err);
      return res.status(500).json({
        success: false,
        message: "Search Failed",
        error: err
      });
    }

    return res.json({
      success: true,
      data: results,
      count: results.length
    });
  });
});

// Get all events by organizer ID (alternative endpoint)
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

// Create event
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

  // Generate ACTxxxxxx
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

// Edit event by ID
app.put("/event/edit/:id", (req, res) => {
  const { id } = req.params;
  const {
    activity_id,
    title,
    description,
    location,
    open_date,
    close_date,
    status,
    image,
    organizer_id,
    organizer_name
  } = req.body;

  if (!id || !activity_id || !title) {
    return res.status(400).json({
      success: false,
      message: "Missing required fields: id, activity_id, title"
    });
  }

  const sql = `
    UPDATE event 
    SET 
      activity_id = ?,
      title = ?,
      description = ?,
      location = ?,
      open_date = ?,
      close_date = ?,
      status = ?,
      image = ?,
      organizer_id = ?,
      organizer_name = ?
    WHERE id = ?
  `;

  const params = [
    activity_id,
    title,
    description || null,
    location || null,
    open_date || null,
    close_date || null,
    status || null,
    image || null,
    organizer_id || null,
    organizer_name || null,
    id
  ];

  db.query(sql, params, (err, result) => {
    if (err) {
      console.error("❌ UPDATE EVENT ERROR:", err);
      return res.status(500).json({
        success: false,
        message: "Update failed",
        error: err.message
      });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({
        success: false,
        message: "Event not found"
      });
    }

    return res.json({
      success: true,
      message: "Event updated successfully",
      id: id
    });
  });
});

// Delete event by ID
app.delete("/event/delete/:id", (req, res) => {
  const { id } = req.params;

  if (!id) {
    return res.status(400).json({
      success: false,
      message: "Event ID is required"
    });
  }

  const sql = "DELETE FROM event WHERE id = ?";

  db.query(sql, [id], (err, result) => {
    if (err) {
      console.error("❌ DELETE EVENT ERROR:", err);
      return res.status(500).json({
        success: false,
        message: "Delete failed",
        error: err.message
      });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({
        success: false,
        message: "Event not found"
      });
    }

    return res.json({
      success: true,
      message: "Event deleted successfully",
      deletedRows: result.affectedRows
    });
  });
});

// Register for event
app.post("/register-event", (req, res) => {
  const {
    activity_id,
    organizer_name,
    firstname,
    lastname,
    phone,
  } = req.body;

  if (!activity_id || !firstname || !lastname || !phone) {
    return res.status(400).json({
      success: false,
      message: "ข้อมูลไม่ครบ",
    });
  }

  const sql = `
    INSERT INTO register_event
    (activity_id, organizer_name, firstname, lastname, phone)
    VALUES (?, ?, ?, ?, ?)
  `;

  db.query(
    sql,
    [activity_id, organizer_name, firstname, lastname, phone],
    (err, result) => {
      if (err) {
        console.error(err);
        return res.status(500).json({
          success: false,
          message: "บันทึกข้อมูลไม่สำเร็จ",
        });
      }

      res.status(201).json({
        success: true,
        message: "ลงทะเบียนสำเร็จ",
        register_id: result.insertId,
      });
    }
  );
});

// ========== TABLE INFO ENDPOINTS ==========

// Get all tables info
app.get("/table/get", (req, res) => {
  const sql = `
    SELECT 
      TABLE_CATALOG,
      TABLE_SCHEMA,
      TABLE_NAME,
      TABLE_TYPE,
      ENGINE,
      VERSION,
      ROW_FORMAT,
      TABLE_ROWS,
      AVG_ROW_LENGTH,
      DATA_LENGTH,
      MAX_DATA_LENGTH,
      INDEX_LENGTH,
      DATA_FREE,
      AUTO_INCREMENT,
      CREATE_TIME,
      UPDATE_TIME,
      CHECK_TIME,
      TABLE_COLLATION,
      CHECKSUM,
      CREATE_OPTIONS,
      TABLE_COMMENT
    FROM information_schema.TABLES
    WHERE TABLE_SCHEMA = DATABASE()
  `;

  db.query(sql, (err, results) => {
    if (err) {
      console.error("❌ GET TABLES ERROR:", err);
      return res.status(500).json({
        success: false,
        message: "Failed to fetch tables",
        error: err.message
      });
    }

    return res.json({
      success: true,
      data: results,
      count: results.length
    });
  });
});

// Get table info by name
app.get("/table/:tableName", (req, res) => {
  const { tableName } = req.params;

  if (!tableName) {
    return res.status(400).json({
      success: false,
      message: "Table name is required"
    });
  }

  const sql = `
    SELECT 
      TABLE_CATALOG,
      TABLE_SCHEMA,
      TABLE_NAME,
      TABLE_TYPE,
      ENGINE,
      VERSION,
      ROW_FORMAT,
      TABLE_ROWS,
      AVG_ROW_LENGTH,
      DATA_LENGTH,
      MAX_DATA_LENGTH,
      INDEX_LENGTH,
      DATA_FREE,
      AUTO_INCREMENT,
      CREATE_TIME,
      UPDATE_TIME,
      CHECK_TIME,
      TABLE_COLLATION,
      CHECKSUM,
      CREATE_OPTIONS,
      TABLE_COMMENT
    FROM information_schema.TABLES
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?
  `;

  db.query(sql, [tableName], (err, results) => {
    if (err) {
      console.error("❌ GET TABLE ERROR:", err);
      return res.status(500).json({
        success: false,
        message: "Failed to fetch table",
        error: err.message
      });
    }

    if (results.length === 0) {
      return res.status(404).json({
        success: false,
        message: `Table '${tableName}' not found`
      });
    }

    return res.json({
      success: true,
      data: results[0]
    });
  });
});

// Get table columns
app.get("/table/:tableName/columns", (req, res) => {
  const { tableName } = req.params;

  if (!tableName) {
    return res.status(400).json({
      success: false,
      message: "Table name is required"
    });
  }

  const sql = `
    SELECT 
      COLUMN_NAME,
      ORDINAL_POSITION,
      COLUMN_DEFAULT,
      IS_NULLABLE,
      DATA_TYPE,
      CHARACTER_MAXIMUM_LENGTH,
      NUMERIC_PRECISION,
      NUMERIC_SCALE,
      COLUMN_KEY,
      EXTRA,
      COLUMN_COMMENT
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?
    ORDER BY ORDINAL_POSITION
  `;

  db.query(sql, [tableName], (err, results) => {
    if (err) {
      console.error("❌ GET COLUMNS ERROR:", err);
      return res.status(500).json({
        success: false,
        message: "Failed to fetch columns",
        error: err.message
      });
    }

    return res.json({
      success: true,
      data: results,
      count: results.length
    });
  });
});

// Get table size
app.get("/table/:tableName/size", (req, res) => {
  const { tableName } = req.params;

  if (!tableName) {
    return res.status(400).json({
      success: false,
      message: "Table name is required"
    });
  }

  const sql = `
    SELECT 
      TABLE_NAME,
      ROUND(((data_length + index_length) / 1024 / 1024), 2) AS size_mb,
      TABLE_ROWS,
      ROUND((data_length / TABLE_ROWS), 2) AS avg_row_size_bytes
    FROM information_schema.TABLES
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?
  `;

  db.query(sql, [tableName], (err, results) => {
    if (err) {
      console.error("❌ GET TABLE SIZE ERROR:", err);
      return res.status(500).json({
        success: false,
        message: "Failed to fetch table size",
        error: err.message
      });
    }

    if (results.length === 0) {
      return res.status(404).json({
        success: false,
        message: `Table '${tableName}' not found`
      });
    }

    return res.json({
      success: true,
      data: results[0]
    });
  });
});

// Get all tables size
app.get("/tables/size/all", (req, res) => {
  const sql = `
    SELECT 
      TABLE_NAME,
      ROUND(((data_length + index_length) / 1024 / 1024), 2) AS size_mb,
      TABLE_ROWS,
      ROUND((data_length / TABLE_ROWS), 2) AS avg_row_size_bytes
    FROM information_schema.TABLES
    WHERE TABLE_SCHEMA = DATABASE()
    ORDER BY (data_length + index_length) DESC
  `;

  db.query(sql, (err, results) => {
    if (err) {
      console.error("❌ GET ALL TABLES SIZE ERROR:", err);
      return res.status(500).json({
        success: false,
        message: "Failed to fetch tables size",
        error: err.message
      });
    }

    return res.json({
      success: true,
      data: results,
      count: results.length
    });
  });
});

// ========== PORTFOLIO ENDPOINTS ==========

// ================= CREATE PORTFOLIO =================

app.post(
  "/createport",
  verifyToken,
  upload.fields([
    { name: "profile", maxCount: 1 },
    { name: "transcript", maxCount: 1 },
    { name: "certificate", maxCount: 20 }
  ]),
  async (req, res) => {

    const connection = await db.promise().getConnection();

    try {
      await connection.beginTransaction();

      let parsedBody = req.body;

      if (typeof req.body.data === "string") {
        parsedBody = JSON.parse(req.body.data);
      }

      const {
        user_id,
        port_id,
        personal_info,
        educational,
        skills_abilities,
        activities_certificates,
        university_choice
      } = parsedBody;

      if (!user_id || !port_id) {
        return res.status(400).json({
          success: false,
          message: "user_id และ port_id จำเป็นต้องมี"
        });
      }

      // ================= Upload Files =================

      let profileUrl = null;
      if (req.files?.profile?.[0]) {
        profileUrl = await uploadToS3(req.files.profile[0], "profile-port");
      }

      let transcriptUrl = null;
      if (req.files?.transcript?.[0]) {
        transcriptUrl = await uploadToS3(req.files.transcript[0], "transcript");
      }

      let certificateUrls = [];

      if (req.files?.certificate?.length) {
        for (const file of req.files.certificate) {
          const url = await uploadToS3(file, "certificates");
          certificateUrls.push(url);
        }
      }

      // ================= portfolios =================

      await connection.query(
        `INSERT INTO portfolios (user_id, port_id, profile_url)
         VALUES (?, ?, ?)`,
        [user_id, port_id, profileUrl]
      );

      // ================= personal_info =================

      if (personal_info) {
        await connection.query(
          `INSERT INTO personal_info
          (port_id, portfolio_name, introduce, prefix, first_name, last_name, date_birth,
           nationality, national_id, phone_number1, phone_number2, email, address,
           province, district, subdistrict, postal_code)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            port_id,
            personal_info.portfolio_name || null,
            personal_info.introduce || null,
            personal_info.prefix || null,
            personal_info.first_name || null,
            personal_info.last_name || null,
            personal_info.date_birth || null,
            personal_info.nationality || null,
            personal_info.national_id || null,
            personal_info.phone_number1 || null,
            personal_info.phone_number2 || null,
            personal_info.email || null,
            personal_info.address || null,
            personal_info.province || null,
            personal_info.district || null,
            personal_info.subdistrict || null,
            personal_info.postal_code || null
          ]
        );
      }

      // ================= educational =================

      if (Array.isArray(educational)) {
        for (const edu of educational) {
          await connection.query(
            `INSERT INTO educational
            (port_id, number, school, graduation, educational_qualifications,
             province, district, study_path, grade_average, study_results)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
              port_id,
              edu.number || null,
              edu.school || null,
              edu.graduation || null,
              edu.educational_qualifications || null,
              edu.province || null,
              edu.district || null,
              edu.study_path || null,
              edu.grade_average || null,
              transcriptUrl || null
            ]
          );
        }
      }

      // ================= skills =================

      if (skills_abilities) {

        const [skillRes] = await connection.query(
          `INSERT INTO skills_abilities (port_id, details)
           VALUES (?, ?)`,
          [port_id, skills_abilities.details || null]
        );

        const skillsId = skillRes.insertId;

        if (Array.isArray(skills_abilities.language_skills)) {

          for (const lang of skills_abilities.language_skills) {

            await connection.query(
              `INSERT INTO language_skills
               (port_id, skills_abilities_id, language, listening, speaking, reading, writing)
               VALUES (?, ?, ?, ?, ?, ?, ?)`,
              [
                port_id,
                skillsId,
                lang.language || null,
                lang.listening || null,
                lang.speaking || null,
                lang.reading || null,
                lang.writing || null
              ]
            );
          }

        }

      }

      // ================= activities =================

      if (Array.isArray(activities_certificates)) {

        for (const activity of activities_certificates) {

          await connection.query(
            `INSERT INTO activities_certificates
             (port_id, number, name_project, date, photo, details)
             VALUES (?, ?, ?, ?, ?, ?)`,
            [
              port_id,
              activity.number || null,
              activity.name_project || null,
              activity.date || null,
              JSON.stringify(certificateUrls),
              activity.details || null
            ]
          );

        }

      }

      // ================= university =================

      if (Array.isArray(university_choice)) {

        for (const uni of university_choice) {

          await connection.query(
            `INSERT INTO university_choice
             (port_id, university, faculty, major, details)
             VALUES (?, ?, ?, ?, ?)`,
            [
              port_id,
              uni.university || null,
              uni.faculty || null,
              uni.major || null,
              uni.details || null
            ]
          );

        }

      }

      await connection.commit();

      return res.json({
        success: true,
        message: "สร้าง Portfolio สำเร็จ",
        uploaded: {
          profile: profileUrl,
          transcript: transcriptUrl,
          certificates: certificateUrls
        }
      });

    } catch (err) {

      await connection.rollback();

      console.error("Create Portfolio Error:", err);

      return res.status(500).json({
        success: false,
        error: err.message
      });

    } finally {

      connection.release();

    }

  }
);


// ===== Get all data portfolio =======
app.get("/getport/:userid", async (req, res) => {
  const { userid } = req.params;
  if (!userid) return res.status(400).json({ success: false, message: "User id required" });

  try {
    const pool = db.promise();

    // 1) Get all port_id for this user
    const [ports] = await pool.query("SELECT port_id, profile_url FROM Daily_Life_DB.portfolios WHERE user_id = ?", [userid]);


    if (!ports || ports.length === 0) {
      return res.json({ pulldata: "success", user_id: userid, portfolio_count: 0, data: [] });
    }

    return res.json({
      success: true,
      user_id: userid,
      portfolio_count: ports.length,
      data: ports
    });
  } catch (err) {
    console.error("❌ GET PORT ERROR:", err);
    return res.status(500).json({ success: false, message: "Search Failed", error: err.message });
  }
});

app.get("/getpersonal_info/:port_id", async (req, res) => {
  const { port_id } = req.params;
  if (!port_id) return res.status(400).json({ success: false, message: "Port id required" });

  try {
    const pool = db.promise();

    // 1) Get all port_id for this user
    const [ports] = await pool.query("SELECT portfolio_name, introduce, prefix, first_name, last_name, date_birth, nationality, national_id, phone_number1, phone_number2, email, address, province, district, subdistrict, postal_code FROM Daily_Life_DB.personal_info WHERE port_id = ?", [port_id]);


    if (!ports || ports.length === 0) {
      return res.json({ pulldata: "success", port_id: port_id, data: [] });
    }

    return res.json({
      success: true,
      port_id: port_id,
      data: ports
    });
  } catch (err) {
    console.error("❌ GET PORT ERROR:", err);
    return res.status(500).json({ success: false, message: "Search Failed", error: err.message });
  }
});

app.get("/geteducational/:port_id", async (req, res) => {
  const { port_id } = req.params;
  if (!port_id) return res.status(400).json({ success: false, message: "Port id required" });

  try {
    const pool = db.promise();

    // 1) Get all port_id for this user
    const [ports] = await pool.query("SELECT `number`, school, graduation, educational_qualifications, province, district, study_path, grade_average, study_results FROM Daily_Life_DB.educational WHERE port_id = ?", [port_id]);


    if (!ports || ports.length === 0) {
      return res.json({ pulldata: "success", port_id: port_id, data: [] });
    }

    return res.json({
      success: true,
      port_id: port_id,
      data: ports
    });
  } catch (err) {
    console.error("❌ GET PORT ERROR:", err);
    return res.status(500).json({ success: false, message: "Search Failed", error: err.message });
  }
});

// Get skills_abilities by port_id (including language_skills)
app.get("/getskills_abilities/:port_id", async (req, res) => {
  const { port_id } = req.params;
  if (!port_id) return res.status(400).json({ success: false, message: "Port id required" });

  try {
    const pool = db.promise();

    // 1) Get all port_id for this user
    const [ports] = await pool.query("SELECT s.id, s.port_id, s.details, l.skills_abilities_id, l.language, l.listening, l.speaking, l.reading, l.writing FROM Daily_Life_DB.skills_abilities s LEFT JOIN Daily_Life_DB.language_skills l ON s.id = l.skills_abilities_id WHERE s.port_id = ?", [port_id]);


    if (!ports || ports.length === 0) {
      return res.json({ pulldata: "success", port_id: port_id, data: [] });
    }

    return res.json({
      success: true,
      port_id: port_id,
      data: ports
    });
  } catch (err) {
    console.error("❌ GET PORT ERROR:", err);
    return res.status(500).json({ success: false, message: "Search Failed", error: err.message });
  }
});

// Get activities_certificates by port_id (including certificate URLs)
app.get("/getactivities_certificates/:port_id", async (req, res) => {
  const { port_id } = req.params;
  if (!port_id) return res.status(400).json({ success: false, message: "Port id required" });

  try {
    const pool = db.promise();

    // 1) Get all port_id for this user
    const [ports] = await pool.query("SELECT id, port_id, `number`, name_project, `date`, photo, details FROM Daily_Life_DB.activities_certificates WHERE port_id = ?", [port_id]);

    if (!ports || ports.length === 0) {
      return res.json({ pulldata: "success", port_id: port_id, data: [] });
    }

    return res.json({
      success: true,
      port_id: port_id,
      data: ports
    });
  } catch (err) {
    console.error("❌ GET PORT ERROR:", err);
    return res.status(500).json({ success: false, message: "Search Failed", error: err.message });
  }
});

app.get("/getuniversity_choice/:port_id", async (req, res) => {
  const { port_id } = req.params;
  if (!port_id) return res.status(400).json({ success: false, message: "Port id required" });

  try {
    const pool = db.promise();

    // 1) Get all port_id for this user
    const [ports] = await pool.query("SELECT id, port_id, university, faculty, major, details FROM Daily_Life_DB.university_choice WHERE port_id = ?", [port_id]);


    if (!ports || ports.length === 0) {
      return res.json({ pulldata: "success", port_id: port_id, data: [] });
    }

    return res.json({
      success: true,
      port_id: port_id,
      data: ports
    });
  } catch (err) {
    console.error("❌ GET PORT ERROR:", err);
    return res.status(500).json({ success: false, message: "Search Failed", error: err.message });
  }
});

// ========== S3 ENDPOINTS ==========

// S3 presigned URL for event photos
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

// Direct S3 upload for event photos
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

// Direct S3 upload for transcript
app.post('/s3/transcript', verifyToken, upload.single('image'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ message: 'No file uploaded' });

    const file = req.file;
    const allowed = ['image/jpeg', 'image/png', 'image/webp'];
    if (!allowed.includes(file.mimetype)) {
      return res.status(400).json({ message: 'Invalid file type' });
    }

    const key = `Transcript/${Date.now()}-${uuidv4()}-${file.originalname.replace(/\s+/g,'_')}`;

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

// S3 presigned URL for transcript
app.post("/s3/presign/transcript", verifyToken, async (req, res) => {
  const { fileName, fileType } = req.body;
  const allowedTypes = ["image/jpeg", "image/png", "image/webp"];

  if (!allowedTypes.includes(fileType)) {
    return res.status(400).json({ message: "Invalid file type" });
  }

  const key = `Transcript/${Date.now()}-${fileName}`;

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

// ========== ERROR HANDLING ==========

// Multer error handler
app.use((err, req, res, next) => {
  if (err && err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ message: 'File too large. Max size is 20MB.' });
    }
    return res.status(400).json({ message: err.message });
  }
  next(err);
});

// ========== START SERVER ==========
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`🚀 Backend running on port ${PORT}`);
});