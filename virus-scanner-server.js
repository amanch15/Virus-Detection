require('dotenv').config();
const express = require('express');
const multer = require('multer');
const axios = require('axios');
const mongoose = require('mongoose');
const fs = require('fs');
const path = require('path');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');
const mongoSanitize = require('express-mongo-sanitize');
const { v4: uuidv4 } = require('uuid');
const fileType = require('file-type');

const app = express();
const PORT = process.env.PORT || 3000;

// Enhanced configuration
const config = {
  maxFileSize: process.env.MAX_FILE_SIZE || 10 * 1024 * 1024, // 10MB default
  allowedMimeTypes: [
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'text/plain',
    'application/rtf',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/vnd.ms-powerpoint',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'application/vnd.oasis.opendocument.text',
    'application/vnd.oasis.opendocument.spreadsheet',
    'application/vnd.oasis.opendocument.presentation'
  ],
  scanResultTtl: process.env.SCAN_RESULT_TTL || 30 * 24 * 60 * 60 * 1000 // 30 days
};

// Security middleware
app.use(helmet());
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type']
}));
app.use(mongoSanitize());
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later'
});
app.use('/upload', apiLimiter);

// MongoDB connection with enhanced options
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/virus_scanner';

mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useCreateIndex: true,
  useFindAndModify: false,
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000
}).then(() => {
  console.log('Connected to MongoDB');
}).catch(err => {
  console.error('MongoDB connection error:', err);
  process.exit(1);
});

// Enhanced Document schema with indexing and validation
const documentSchema = new mongoose.Schema({
  scanId: { 
    type: String, 
    required: true,
    unique: true,
    default: () => uuidv4()
  },
  filename: { 
    type: String, 
    required: true,
    trim: true
  },
  originalName: { 
    type: String, 
    required: true,
    trim: true
  },
  uploadDate: { 
    type: Date, 
    default: Date.now,
    index: { expires: config.scanResultTtl }
  },
  scanDate: { 
    type: Date 
  },
  fileSize: { 
    type: Number,
    min: 0
  },
  mimeType: {
    type: String,
    required: true
  },
  isInfected: { 
    type: Boolean, 
    default: false 
  },
  scanMessage: { 
    type: String,
    trim: true
  },
  scanDetails: { 
    type: mongoose.Schema.Types.Mixed 
  },
  sha256: {
    type: String,
    trim: true
  },
  userId: {
    type: String,
    default: null
  }
}, {
  timestamps: true,
  toJSON: {
    virtuals: true,
    transform: (doc, ret) => {
      delete ret._id;
      delete ret.__v;
      return ret;
    }
  }
});

// Add virtual for formatted file size
documentSchema.virtual('formattedSize').get(function() {
  if (this.fileSize === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(this.fileSize) / Math.log(k));
  return parseFloat((this.fileSize / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
});

const Document = mongoose.model('Document', documentSchema);

// Enhanced file upload configuration with validation
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = 'uploads';
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${uuidv4()}${ext}`);
  }
});

const fileFilter = (req, file, cb) => {
  if (config.allowedMimeTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Invalid file type. Only document files are allowed.'), false);
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: { 
    fileSize: config.maxFileSize,
    files: 1
  }
});

// VirusTotal API service
class VirusTotalService {
  constructor(apiKey) {
    this.apiKey = apiKey;
    this.baseUrl = 'https://www.virustotal.com/api/v3';
  }

  async scanFile(filePath) {
    try {
      const fileData = fs.readFileSync(filePath);
      const fileInfo = await fileType.fromBuffer(fileData);

      // Validate file type matches extension
      if (!fileInfo || !config.allowedMimeTypes.includes(fileInfo.mime)) {
        throw new Error('File content does not match the expected type');
      }

      const response = await axios.post(`${this.baseUrl}/files`, fileData, {
        headers: {
          'x-apikey': this.apiKey,
          'Content-Type': 'application/octet-stream'
        },
        maxContentLength: Infinity,
        maxBodyLength: Infinity
      });

      return response.data;
    } catch (error) {
      console.error('VirusTotal scan error:', error.message);
      throw new Error(`Failed to scan file: ${error.message}`);
    }
  }

  async getAnalysisReport(analysisId) {
    try {
      const response = await axios.get(`${this.baseUrl}/analyses/${analysisId}`, {
        headers: { 'x-apikey': this.apiKey }
      });
      return response.data;
    } catch (error) {
      console.error('VirusTotal report error:', error.message);
      throw new Error(`Failed to get analysis report: ${error.message}`);
    }
  }
}

const vtService = new VirusTotalService(process.env.VIRUSTOTAL_API_KEY);

// Utility functions
const calculateFileHash = async (filePath) => {
  const crypto = require('crypto');
  const hash = crypto.createHash('sha256');
  const fileData = fs.readFileSync(filePath);
  hash.update(fileData);
  return hash.digest('hex');
};

const cleanupFile = (filePath) => {
  if (fs.existsSync(filePath)) {
    fs.unlink(filePath, err => {
      if (err) console.error('Error deleting temp file:', err);
    });
  }
};

// API endpoints

/**
 * @api {post} /upload Upload and scan document
 * @apiName UploadDocument
 * @apiGroup Scanner
 * 
 * @apiParam {File} document The file to scan
 * 
 * @apiSuccess {Boolean} success True if the operation was successful
 * @apiSuccess {Boolean} infected True if the file is infected
 * @apiSuccess {String} message Status message
 * @apiSuccess {String} scanId Unique scan ID
 * @apiSuccess {Object} scanDetails Scan results details
 */
app.post('/upload', upload.single('document'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ 
        success: false, 
        error: 'No file uploaded or file type not allowed' 
      });
    }

    const { filename, originalname, size, mimetype, path: filePath } = req.file;

    // Calculate file hash
    const fileHash = await calculateFileHash(filePath);

    // Check if this file was already scanned
    const existingScan = await Document.findOne({ sha256: fileHash });
    if (existingScan) {
      cleanupFile(filePath);
      return res.json({
        success: true,
        infected: existingScan.isInfected,
        message: existingScan.scanMessage,
        scanId: existingScan.scanId,
        scanDetails: existingScan.scanDetails,
        cached: true
      });
    }

    // Scan the file with VirusTotal
    const scanResult = await vtService.scanFile(filePath);
    const isInfected = scanResult.data.attributes.last_analysis_stats.malicious > 0;
    const scanMessage = isInfected ? 
      'Virus detected! File rejected.' : 
      'File is clean and safe to use.';

    // Save scan results
    const documentRecord = new Document({
      filename,
      originalName: originalname,
      fileSize: size,
      mimeType: mimetype,
      scanDate: new Date(),
      isInfected,
      scanMessage,
      scanDetails: scanResult.data.attributes.last_analysis_results,
      sha256: fileHash
    });

    await documentRecord.save();

    // Clean up temp file
    cleanupFile(filePath);

    // Return appropriate response
    if (isInfected) {
      return res.status(400).json({
        success: false,
        infected: true,
        message: scanMessage,
        scanId: documentRecord.scanId,
        scanDetails: documentRecord.scanDetails
      });
    }

    return res.json({
      success: true,
      infected: false,
      message: scanMessage,
      scanId: documentRecord.scanId,
      scanDetails: documentRecord.scanDetails
    });

  } catch (error) {
    console.error('Upload error:', error.message);
    
    // Clean up temp file if exists
    if (req.file && req.file.path) {
      cleanupFile(req.file.path);
    }

    return res.status(500).json({ 
      success: false, 
      error: error.message || 'Internal server error during file processing' 
    });
  }
});

/**
 * @api {get} /scan/:scanId Get scan results
 * @apiName GetScanResults
 * @apiGroup Scanner
 * 
 * @apiParam {String} scanId The scan ID to retrieve
 * 
 * @apiSuccess {Boolean} success True if the operation was successful
 * @apiSuccess {Object} document The scan results document
 */
app.get('/scan/:scanId', async (req, res) => {
  try {
    const { scanId } = req.params;
    const document = await Document.findOne({ scanId });

    if (!document) {
      return res.status(404).json({ 
        success: false, 
        error: 'Scan results not found' 
      });
    }

    return res.json({
      success: true,
      document
    });

  } catch (error) {
    console.error('Scan results error:', error.message);
    return res.status(500).json({ 
      success: false, 
      error: 'Internal server error while fetching scan results' 
    });
  }
});

/**
 * @api {get} /stats Get scanning statistics
 * @apiName GetStats
 * @apiGroup Scanner
 * 
 * @apiSuccess {Boolean} success True if the operation was successful
 * @apiSuccess {Object} stats Scanning statistics
 */
app.get('/stats', async (req, res) => {
  try {
    const totalScans = await Document.countDocuments();
    const infectedCount = await Document.countDocuments({ isInfected: true });
    const cleanCount = totalScans - infectedCount;
    const fileTypes = await Document.aggregate([
      { $group: { _id: "$mimeType", count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);

    return res.json({
      success: true,
      stats: {
        totalScans,
        infectedCount,
        cleanCount,
        infectionRate: totalScans > 0 ? (infectedCount / totalScans * 100).toFixed(2) : 0,
        fileTypes
      }
    });

  } catch (error) {
    console.error('Stats error:', error.message);
    return res.status(500).json({ 
      success: false, 
      error: 'Internal server error while fetching statistics' 
    });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Server error:', err.stack);
  
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ 
      success: false, 
      error: err.code === 'LIMIT_FILE_SIZE' ? 
        'File too large. Maximum size is 10MB.' : 
        'File upload error' 
    });
  }

  res.status(500).json({ 
    success: false, 
    error: 'Internal server error' 
  });
});

// Start server
const server = app.listen(PORT, () => {
  console.log(`Virus scanner server running on http://localhost:${PORT}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Shutting down gracefully...');
  server.close(() => {
    mongoose.connection.close(false, () => {
      console.log('Server and MongoDB connection closed');
      process.exit(0);
    });
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT received. Shutting down gracefully...');
  server.close(() => {
    mongoose.connection.close(false, () => {
      console.log('Server and MongoDB connection closed');
      process.exit(0);
    });
  });
});