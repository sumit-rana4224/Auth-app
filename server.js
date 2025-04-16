const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
const axios = require('axios');
const User = require('./models/User');

dotenv.config();
const app = express();
mongoose.connect(process.env.MONGO_URI);

app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true
}));

// --- LOGOUT ROUTE ---
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.send('Error logging out');
    }
    res.redirect('/login.html');
  });
});

// --- SIGNUP ROUTE WITH LOCATION DETECTION ---
app.post('/signup', async (req, res) => {
  const { name, email, password } = req.body;
  const userExist = await User.findOne({ email });
  if (userExist) return res.send('User already exists! <a href="/signup.html">Try again</a>');

  const hashed = await bcrypt.hash(password, 10);

  // Detect IP and get location
  let location = { city: 'Unknown', latitude: '', longitude: '' };
  try {
    const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress || '103.57.85.0'; // fallback IP
    const geo = await axios.get(`https://ipapi.co/${ip}/json/`);
    location = {
      city: geo.data.city || 'Unknown',
      latitude: geo.data.latitude,
      longitude: geo.data.longitude
    };
  } catch (error) {
    console.log('❌ Error detecting location:', error.message);
  }

  await User.create({
    name,
    email,
    password: hashed,
    location: location.city,
    latitude: location.latitude,
    longitude: location.longitude
  });

  res.redirect('/login.html');
});

// --- LOGIN ROUTE ---
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.send('Invalid credentials! <a href="/login.html">Try again</a>');
  }
  req.session.user = {
    name: user.name,
    email: user.email,
    location: user.location,
    latitude: user.latitude,
    longitude: user.longitude
  };
  res.redirect('/dashboard.html');
});

// --- GET CURRENT LOGGED-IN USER ---
app.get('/user', (req, res) => {
  if (!req.session.user) return res.status(401).json({ msg: 'Not logged in' });
  res.json(req.session.user);
});

// --- START SERVER ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
