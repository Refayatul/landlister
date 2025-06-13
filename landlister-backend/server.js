// server.js
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// --- Middleware ---
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// --- MongoDB Connection ---
mongoose.connect('mongodb://localhost:27017/landlisterDB')
.then(() => console.log('MongoDB Connected Successfully'))
.catch(err => {
  console.error('!!! MongoDB Connection Error:', err);
});

// --- Mongoose User Schema and Model ---
const userSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  fatherName: { type: String, required: true },
  nid: { type: String, required: true, unique: true },
  dob: { type: Date, required: true },
  mobileNo: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  registrationDate: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// --- API Routes ---

// Registration Endpoint (Final, Reviewed Version)
app.post('/api/register', async (req, res) => {
  console.log('--- /api/register endpoint hit ---');
  try {
    const { fullName, fatherName, NID, dob, m_n, pw } = req.body;
    console.log("Received registration data:", req.body);

    // 1. Backend validation for presence of all fields
    if (!fullName || !fatherName || !NID || !dob || !m_n || !pw) {
      return res.status(400).json({ message: 'All fields are required.' });
    }

    // 2. Check if NID already exists for a user-friendly error
    const existingUserByNID = await User.findOne({ nid: NID });
    if (existingUserByNID) {
      return res.status(400).json({
        message: `This NID (${NID}) is already registered. Please try logging in.`
      });
    }

    // 3. Check if mobile number already exists for a user-friendly error
    const existingUserByMobile = await User.findOne({ mobileNo: m_n });
    if (existingUserByMobile) {
      return res.status(400).json({
        message: `This Mobile Number (${m_n}) is already registered. Please try logging in or use account recovery.`
      });
    }

    // 4. Hash the password for security
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(pw, salt);

    // 5. Create and save the new user
    const newUser = new User({
      fullName,
      fatherName,
      nid: NID,
      dob,
      mobileNo: m_n,
      password: hashedPassword,
    });

    await newUser.save();
    console.log(`User '${fullName}' (NID: ${NID}) registered successfully!`);
    
    // Send a 201 Created status for success
    res.status(201).json({ message: 'User registered successfully! You can now log in.' });

  } catch (error) {
    console.error('!!! ERROR in /api/register:', error);
    // Fallback for database-level unique constraint errors (e.g., race conditions)
    if (error.code === 11000) {
        const field = Object.keys(error.keyValue)[0];
        const value = error.keyValue[field];
        return res.status(400).json({ message: `An account with this ${field} ('${value}') already exists.` });
    }
    // Handle Mongoose-specific validation errors
    if (error.name === 'ValidationError') {
        const messages = Object.values(error.errors).map(val => val.message);
        return res.status(400).json({ message: `Registration failed: ${messages.join('. ')}` });
    }
    // Generic server error for anything else
    res.status(500).json({ message: 'Server error during registration. Please try again later.' });
  }
});


// Login Endpoint (This is the previously fixed version)
app.post('/api/login', async (req, res) => {
  // ... (the fixed login logic from the previous response goes here)
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: 'NID/Mobile Number and password are required.' });
  }
  try {
    const user = await User.findOne({ $or: [{ nid: username }, { mobileNo: username }] });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials. Please check your NID/Mobile and password.' });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials. Please check your NID/Mobile and password.' });
    }
    res.status(200).json({
      message: 'Login successful!',
      user: { id: user._id, fullName: user.fullName, nid: user.nid }
    });
  } catch (error) {
    console.error('!!! ERROR in /api/login:', error);
    res.status(500).json({ message: 'Server error during login.' });
  }
});

// --- Start the Server ---
app.listen(PORT, () => {
  console.log(`Backend server is running on http://localhost:${PORT}`);
});