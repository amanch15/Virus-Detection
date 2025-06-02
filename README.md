# 🛡️ Virus Scanner Server

A secure Node.js backend API that scans uploaded documents for potential threats. Built with Express, Multer, and MongoDB, this backend service is designed for applications that require safe file uploads and robust backend security.



---

## 🔍 Features

- 📤 File upload support using `multer`
- 🧠 File type validation with `file-type`
- 🔐 Security enhancements:
  - `helmet` for HTTP headers
  - `express-rate-limit` for request throttling
  - `express-mongo-sanitize` to prevent injection attacks
- 🧪 Testing setup using `jest` and `supertest`
- 🧱 MongoDB integration with `mongoose`

---


## 🧠 Overview

- **Frontend**: Upload documents and view scan results
- **Backend**: Handle file uploads, file-type detection, and security checks
- **Database**: Store metadata of scanned files


---

## 🖥️ Frontend

### 🔹 Features

- Simple upload interface
- Sends file to backend via `POST /upload`
- Displays scan success/failure message

### 🔹 Technologies

- HTML, CSS, JavaScript (vanilla)
- Axios (for making HTTP requests)

---

## 🧰 Backend

### 🔹 Features

- File uploads via `multer`
- File type validation using `file-type`
- Secure server with:
  - `helmet` (headers)
  - `express-rate-limit` (rate limiting)
  - `express-mongo-sanitize` (injection prevention)
- Stores metadata in MongoDB

### 🔹 Technologies

| Purpose        | Tech Stack / Packages                             |
|----------------|---------------------------------------------------|
| **Runtime**    | Node.js                                           |
| **Framework**  | Express.js                                        |
| **Database**   | MongoDB, Mongoose                                 |
| **File Upload**| Multer                                            |
| **File Type Detection** | File-Type                              |
| **Security**   | Helmet, Express Rate Limit, Express Mongo Sanitize |
| **Testing**    | Jest, Supertest                                   |
| **Environment**| dotenv                                            |
| **UUID Support**| uuid                                             |

---


## 👨‍💻 Author

**Aman Choudhary**  



