# FormOS Backend

This is the Express backend API application for FormOS, a privacy-first AI Document Platform.

## Project Overview
FormOS Backend provides endpoints for user authentication, MFA verification, document storage routing, local and cloud OCR, AI assistant interaction, and the Security V2 cryptographic layer.

---

## Technical Stack
- **Framework**: Express.js (Node.js)
- **Database**: MongoDB (Mongoose ODM)
- **Document Storage**: GridFS (for V2 secure documents) and S3 / Local memory buffer (for V1 documents)
- **OCR Engine**: Tesseract.js (for V1 plaintext extraction)
- **AI Integrations**: OpenRouter, OpenAI, and Google Gemini
- **Security**: Helmet, Express Rate Limit, bcryptjs, JSON Web Tokens (JWT), Speakeasy (TOTP MFA)

---

## Folder Structure
```
config/                 # Database and flag configurations
controllers/            # Request handlers
  authController.js     # User registration, login, and step-up auth
  documentController.js # Document upload, update, download, and secure V2 endpoints
  migrationController.js# V1 to V2 lazy migration controllers
  chatController.js     # Chat API endpoint (blocks V2 server-side RAG)
middleware/             # Router middleware
  auth.js               # JWT verification and step-up validation rules
  requireStepUp.js      # Endpoint re-authentication guard
models/                 # Mongoose schemas (User, Document, Session)
routes/                 # Express API routes (/auth, /documents, /chat, /migration)
services/               # Application-level services
  storageService.js     # S3, GridFS, and Local storage routers
  ragService.js         # Cloud-RAG service (blocked for V2)
  aiService.js          # Cloud-AI integrations with policy checks
```

---

## Security V2 Architecture & Coexistence

The backend enforces strict boundary isolation between Security V1 and V2 accounts.

| Security Version | Document Storage | OCR / Text Extraction | RAG Execution | AI Policy Gate |
| :---: | :--- | :--- | :--- | :--- |
| **V1** | S3 / Local Storage | Server-side (Tesseract) | Server-side Cloud RAG | Allowed (OpenRouter/OpenAI) |
| **V2** | GridFS (Ciphertext Only) | Client-side (Skipped on Server) | Local/Client-side | Blocked (AIPolicyViolationError) |

### Server-Side Security Rejection Rules
1. **Plaintext Upload Guard**: The legacy upload path `POST /api/documents/upload` checks the authenticated user's database record. If the user's `securityVersion === 2`, the upload is rejected with HTTP 403 and error code `V2_PLAINTEXT_UPLOAD_BLOCKED`.
2. **Dedicated V2 Upload Endpoint**: `POST /api/documents/secure-v2/upload` accepts only versioned V2 encrypted envelopes, uploads them directly to GridFS, sets `ocrStatus: 'skipped'`, and restricts access to authenticated V2 users only.
3. **Storage Fallback Protection**: GridFS is hardcoded as the exclusive storage for V2. Fallback to S3 or local disk is strictly blocked.
4. **AI Policy Boundary**: All cloud-AI requests pass through the AI Policy Gate. If a V2 user attempts server-side RAG or sends sensitive unmapped PII fields, the request fails closed.

---

## V1 → V2 Migration Support
The migration endpoints support an idempotent client-driven transaction:
- `POST /api/migration/profile`: Uploads the encrypted V2 profile.
- `POST /api/migration/upload-document/:id`: Uploads a re-encrypted V2 document to a temporary GridFS target.
- `POST /api/migration/commit-document/:id`: Commits the temporary GridFS ID to the document record and deletes the legacy V1 copy from S3/local storage.
- `POST /api/migration/complete`: Marks the user's migration as completed and upgrades `securityVersion` to `2`.
- `POST /api/migration/failed`: Rolls back state on error.

---

## Environment Variables
Create a `FormOSBackend/.env` file containing the following variables:
- `PORT` (e.g. `5000`)
- `MONGODB_URI` (MongoDB connection string)
- `JWT_SECRET` (token secret)
- `MFA_APP_NAME` (e.g. `FormOS`)
- `MAX_FILE_SIZE` (default 10MB)
- AWS environment variables (for legacy S3 support): `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`, `S3_BUCKET_NAME`
- AI Provider keys: `OPENROUTER_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`

---

## Development Setup

### Prerequisites
- Node.js >= 18
- Running MongoDB instance

### Installation
```bash
npm install
```

### Run Dev Server
```bash
npm run dev
```

### Run Test Suites
Ensure you have test dependencies installed locally:
```bash
# Run migration suite
node run-migration-tests.js

# Run RAG & document protection suite
node -e "require('ts-node').register({ compilerOptions: { module: 'commonjs', moduleResolution: 'node', target: 'ES2020' } }); require('./test-rag.ts');"

# Run autofill suite
node -e "require('ts-node').register({ compilerOptions: { module: 'commonjs', moduleResolution: 'node', target: 'ES2020' } }); require('./test-autofill.ts');"

# Run AI policy guards
node test-ai-policy.js

# Run foundation schemas tests
node test-security-v2-foundation.js
```

---

## Deprecation & S3 Roadmap
- **Legacy S3**: Retained for backward-compatible storage of unmigrated V1 files and to facilitate active V1-to-V2 lazy migrations.
- **S3 De-provisioning [DEFERRED]**: Once the database shows zero remaining V1 documents and all users have completed V2 migration, the `@aws-sdk/client-s3` library and `s3` storage types will be fully de-provisioned.
