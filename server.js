require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const connectDB = require('./config/database');

const app = express();

// Connect to MongoDB
connectDB();

// Trust proxy (required when running behind Render/nginx/load balancers)
app.set('trust proxy', 1);

// Middleware
app.use(helmet());
const ALLOWED_ORIGINS = [
  'http://localhost:3000',
  'http://localhost:3001',
  'https://formos.online',
  'https://www.formos.online',
  'https://api.formos.online',
  ...(process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim()) : []),
];

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (mobile apps, curl, Postman)
    if (!origin) return callback(null, true);
    // Allow any chrome-extension origin
    if (origin.startsWith('chrome-extension://')) return callback(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
    callback(new Error(`CORS: origin ${origin} not allowed`));
  },
  credentials: true,
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Routes
app.use('/api/auth', require('./routes/auth'));
app.use('/api/documents', require('./routes/documents'));
app.use('/api/chat', require('./routes/chat'));
app.use('/api/autofill', require('./routes/autofill'));
app.use('/api/form-analyzer', require('./routes/formAnalyzer'));
app.use('/api/eligibility', require('./routes/eligibility'));
app.use('/api/extension', require('./routes/extension'));
app.use('/api/migration', require('./routes/migration'));

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', message: 'FormOS API is running' });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(err.status || 500).json({
    success: false,
    message: err.message || 'Internal server error'
  });
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`🚀 FormOS Backend running on port ${PORT}`);
});
