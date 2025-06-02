SecureDoc Scanner
SecureDoc Scanner is an advanced web-based document security analysis tool that allows users to upload and scan documents for potential threats. It features a user-friendly interface with drag-and-drop functionality and provides real-time scanning progress and results. The backend is powered by Node.js, Express, and integrates with the VirusTotal API for comprehensive virus detection.

Features
Drag & Drop File Upload: Easily upload documents by dragging and dropping them into the designated area or by selecting them through a file input.
Supported Document Types: Scans common document formats including PDF, DOCX, XLSX, PPTX, TXT, RTF, DOC, XLS, and PPT.
Real-time Scan Progress: Displays scanning status, progress percentage, and estimated time remaining.
Detailed Scan Results: Provides clear indications of whether a document is clean, contains suspicious elements, or is infected with malware.
File Information Display: Shows file name, size, type, and upload date.
VirusTotal Integration: Leverages the VirusTotal API for robust and up-to-date threat detection.
Backend API: Provides endpoints for document uploads, retrieving scan results, and scanning statistics.
MongoDB Integration: Stores scan results, including infection status, scan messages, and details, with a configurable time-to-live (TTL) for results.
Security Middleware: Includes helmet, cors, express-mongo-sanitize, and express-rate-limit for enhanced API security.
File Hashing for Caching: Uses SHA256 hashing to check for previously scanned files, returning cached results if available.
Graceful Shutdown: Handles SIGTERM and SIGINT signals for clean server shutdown.
Technologies Used
Frontend
HTML5
CSS3
JavaScript (Vanilla JS)
Font Awesome (for icons)
Backend
Node.js
Express.js
MongoDB (with Mongoose)
Multer (for file uploads)
Axios (for HTTP requests to VirusTotal)
file-type (for file type detection)
uuid (for unique IDs)
dotenv (for environment variables)
helmet, cors, express-mongo-sanitize, express-rate-limit (for security)
