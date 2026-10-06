require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { GoogleGenAI } = require('@google/genai');

const PORT = process.env.PORT || 5001;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// =========================
// USER SCHEMA
// =========================

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },

  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
    match: [
      /^[a-zA-Z0-9+_.-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
      'Please provide a valid email address'
    ]
  },

  password: {
    type: String,
    required: true,
    minlength: 6
  }
}, {
  timestamps: true
});

// Password compare only
userSchema.methods.matchPassword = async function(password) {
  return bcrypt.compare(password, this.password);
};

const User = mongoose.model('User', userSchema);

// =========================
// LOCATION SCHEMA
// =========================

const locationSchema = new mongoose.Schema({
  city: {
    type: String,
    required: true,
    trim: true
  },

  country: {
    type: String,
    required: true,
    trim: true
  },

  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  }
}, {
  timestamps: true
});

locationSchema.index(
  {
    user: 1,
    city: 1,
    country: 1
  },
  {
    unique: true
  }
);

const Location = mongoose.model('Location', locationSchema);

// =========================
// AUTH MIDDLEWARE
// =========================

async function protect(req, res, next) {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        message: 'Not authorized, access token missing.'
      });
    }

    const token = authHeader.split(' ')[1];

    const decoded = jwt.verify(token, JWT_SECRET);

    const user = await User.findById(decoded.id).select('-password');

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'User no longer exists.'
      });
    }

    req.user = user;

    return next();

  } catch (error) {
    return res.status(401).json({
      success: false,
      message: 'Invalid or expired token.'
    });
  }
}

// =========================
// JWT
// =========================

function generateToken(id) {
  return jwt.sign(
    { id: id },
    JWT_SECRET,
    {
      expiresIn: '30d'
    }
  );
}

// =========================
// REGISTER
// =========================

app.post('/api/auth/register', async (req, res) => {
  try {

    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Name, email and password are required.'
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 6 characters.'
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const existingUser = await User.findOne({
      email: normalizedEmail
    });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'User already exists.'
      });
    }

    // Hash password here
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await User.create({
      name: name.trim(),
      email: normalizedEmail,
      password: hashedPassword
    });

    const token = generateToken(user._id);

    return res.status(201).json({
      success: true,
      data: {
        _id: user._id,
        name: user.name,
        email: user.email,
        token: token
      }
    });

  } catch (error) {

    console.error('REGISTER ERROR:', error);

    return res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// =========================
// LOGIN
// =========================

app.post('/api/auth/login', async (req, res) => {
  try {

    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email and password are required.'
      });
    }

    const user = await User.findOne({
      email: email.trim().toLowerCase()
    });

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password.'
      });
    }

    const passwordCorrect = await user.matchPassword(password);

    if (!passwordCorrect) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password.'
      });
    }

    const token = generateToken(user._id);

    return res.status(200).json({
      success: true,
      data: {
        _id: user._id,
        name: user.name,
        email: user.email,
        token: token
      }
    });

  } catch (error) {

    console.error('LOGIN ERROR:', error);

    return res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// =========================
// ADD LOCATION
// =========================

app.post('/api/location', protect, async (req, res) => {
  try {

    const { city, country } = req.body;

    if (!city || !country) {
      return res.status(400).json({
        success: false,
        message: 'City and country are required.'
      });
    }

    const location = await Location.create({
      city: city.trim(),
      country: country.trim(),
      user: req.user._id
    });

    return res.status(201).json({
      success: true,
      data: location
    });

  } catch (error) {

    if (error.code === 11000) {
      return res.status(400).json({
        success: false,
        message: 'Location already added to favorites.'
      });
    }

    return res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// =========================
// GET LOCATIONS
// =========================

app.get('/api/location', protect, async (req, res) => {
  try {

    const locations = await Location.find({
      user: req.user._id
    });

    return res.status(200).json({
      success: true,
      count: locations.length,
      data: locations
    });

  } catch (error) {

    return res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// =========================
// DELETE LOCATION
// =========================

app.delete('/api/location/:id', protect, async (req, res) => {
  try {

    const location = await Location.findOneAndDelete({
      _id: req.params.id,
      user: req.user._id
    });

    if (!location) {
      return res.status(404).json({
        success: false,
        message: 'Location not found.'
      });
    }

    return res.status(200).json({
      success: true,
      message: 'Location removed successfully.'
    });

  } catch (error) {

    return res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// =========================
// WEATHER
// =========================

app.get('/api/weather/:city', async (req, res) => {
  try {

    const city = req.params.city || 'Bangalore';

    return res.status(200).json({
      success: true,
      data: {
        city: city.charAt(0).toUpperCase() + city.slice(1),
        temperature: 34,
        humidity: 79,
        windSpeed: 12,
        condition: 'Windy',
        isMock: true
      }
    });

  } catch (error) {

    return res.status(500).json({
      success: false,
      message: 'Weather metrics compilation error.'
    });
  }
});

// =========================
// GEMINI AI
// =========================

app.post('/api/ai/weather-recommendation', async (req, res) => {
  try {

    const {
      city,
      temperature,
      humidity,
      condition
    } = req.body;

    if (
      !city ||
      temperature === undefined ||
      humidity === undefined ||
      !condition
    ) {
      return res.status(400).json({
        success: false,
        message: 'Weather information is incomplete.'
      });
    }

    if (!GEMINI_API_KEY) {
      return res.status(200).json({
        success: true,
        recommendation:
          'Stay hydrated and wear light cotton clothes.'
      });
    }

    const ai = new GoogleGenAI({
      apiKey: GEMINI_API_KEY
    });

    const prompt = `
Analyze this weather:

City: ${city}
Temperature: ${temperature}°C
Humidity: ${humidity}%
Condition: ${condition}

Give one short outdoor advice sentence.
`;

    const response = await ai.models.generateContent({
      model: 'gemini-2.5-flash',
      contents: prompt
    });

    if (response && response.text) {
      return res.status(200).json({
        success: true,
        recommendation: response.text.trim()
      });
    }

    return res.status(200).json({
      success: true,
      recommendation:
        'Stay hydrated and wear light cotton clothes.'
    });

  } catch (error) {

    console.error('GEMINI ERROR:', error.message);

    return res.status(200).json({
      success: true,
      recommendation:
        'Stay hydrated and wear light cotton clothes.'
    });
  }
});

// =========================
// ERROR HANDLER
// =========================

app.use((err, req, res, next) => {

  console.error('SERVER ERROR:', err);

  return res.status(500).json({
    success: false,
    message: 'Internal Server Error.'
  });
});

// =========================
// ENV CHECK
// =========================

if (!MONGO_URI) {
  console.error('MONGO_URI is missing in .env');
  process.exit(1);
}

if (!JWT_SECRET) {
  console.error('JWT_SECRET is missing in .env');
  process.exit(1);
}

// =========================
// START SERVER
// =========================

mongoose
  .connect(MONGO_URI)
  .then((conn) => {

    console.log(
      `MongoDB Connected: ${conn.connection.host}`
    );

    app.listen(PORT, () => {
      console.log(
        `Server running on http://localhost:${PORT}`
      );
    });

  })
  .catch((error) => {

    console.error(
      'MongoDB connection failed:',
      error.message
    );

    process.exit(1);
  });
