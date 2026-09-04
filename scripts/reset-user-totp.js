const path = require('path');
const fs = require('fs');
require('dotenv').config({ path: path.join(__dirname, '../.env') });
const mongoose = require('mongoose');
const User = require('../models/User');
const {
  generateMfaSecret,
  buildQrCodeDataUrl,
  encryptText,
  createRecoveryCodes
} = require('../services/securityService');

async function resetTotp(email) {
  if (!email) {
    console.error('Please provide an email. Usage: node reset-user-totp.js <email>');
    process.exit(1);
  }

  await mongoose.connect(process.env.MONGODB_URI);
  console.log('Connected to MongoDB.');

  const user = await User.findOne({ email: email.toLowerCase().trim() });
  if (!user) {
    console.error(`User with email "${email}" not found.`);
    await mongoose.disconnect();
    process.exit(1);
  }

  // 1. Generate new TOTP secret
  const mfaSecret = generateMfaSecret(user.email);
  const qrCodeDataUrl = await buildQrCodeDataUrl(mfaSecret.otpauth_url);

  // 2. Encrypt secret
  const { encrypted, iv, authTag } = encryptText(mfaSecret.base32);

  // 3. Generate fresh recovery codes
  const recovery = await createRecoveryCodes();

  // 4. Update user in MongoDB
  user.security = user.security || {};
  user.security.mfa = {
    enabled: true,
    secretEncrypted: encrypted,
    secretIv: iv,
    secretAuthTag: authTag,
    backupCodeHashes: recovery.hashedCodes,
    enabledAt: new Date(),
    lastVerifiedAt: new Date(),
    recoveryCodesGeneratedAt: new Date()
  };

  await user.save();
  console.log('✅ MongoDB user record updated with new TOTP secret & recovery codes.');

  // 5. Generate a beautiful local HTML page to view and scan the QR code
  const htmlContent = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>FormOS - Scan New Authenticator</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #0F172A;
      color: #F8FAFC;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      margin: 0;
      padding: 20px;
    }
    .card {
      background: #1E293B;
      border: 1px solid #334155;
      border-radius: 20px;
      padding: 36px;
      max-width: 480px;
      text-align: center;
      box-shadow: 0 20px 40px rgba(0,0,0,0.4);
    }
    h1 { font-size: 22px; color: #F8FAFC; margin-bottom: 8px; }
    p { font-size: 14px; color: #94A3B8; line-height: 1.5; margin-bottom: 24px; }
    .qr-box {
      background: white;
      padding: 16px;
      border-radius: 16px;
      display: inline-block;
      margin-bottom: 24px;
      box-shadow: 0 4px 15px rgba(0,0,0,0.2);
    }
    .qr-box img { width: 220px; height: 220px; display: block; }
    .manual-key {
      background: #0F172A;
      border: 1px solid #334155;
      padding: 12px 16px;
      border-radius: 10px;
      font-family: monospace;
      font-size: 15px;
      color: #38BDF8;
      letter-spacing: 1.5px;
      word-break: break-all;
      margin-bottom: 24px;
      user-select: all;
    }
    .recovery-title {
      font-size: 13px;
      font-weight: 700;
      color: #E2E8F0;
      text-align: left;
      margin-bottom: 8px;
    }
    .recovery-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 8px;
      background: #0F172A;
      padding: 12px;
      border-radius: 10px;
      font-family: monospace;
      font-size: 12px;
      color: #F8FAFC;
      text-align: center;
      margin-bottom: 20px;
    }
    .badge {
      background: #10B981;
      color: white;
      font-size: 11px;
      font-weight: 700;
      padding: 4px 12px;
      border-radius: 9999px;
      display: inline-block;
      margin-bottom: 16px;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="badge">ACTIVE & READY</div>
    <h1>FormOS Authenticator Setup</h1>
    <p>Scan this QR code with <strong>Google Authenticator</strong>, <strong>Microsoft Authenticator</strong>, or <strong>Authy</strong> for account <strong>${user.email}</strong>.</p>
    
    <div class="qr-box">
      <img src="${qrCodeDataUrl}" alt="Authenticator QR Code" />
    </div>

    <div style="font-size: 12px; color: #64748B; margin-bottom: 6px;">Can't scan? Enter this Secret Key manually:</div>
    <div class="manual-key">${mfaSecret.base32}</div>

    <div class="recovery-title">New Backup Recovery Codes:</div>
    <div class="recovery-grid">
      ${recovery.plainCodes.map(c => `<div>${c}</div>`).join('')}
    </div>
    <p style="font-size: 12px; color: #64748B; margin: 0;">Keep your recovery codes in a safe place in case you lose access to your authenticator app.</p>
  </div>
</body>
</html>`;

  const outputPath = path.join(__dirname, '../reset-authenticator.html');
  fs.writeFileSync(outputPath, htmlContent, 'utf8');

  console.log('\n======================================================');
  console.log('🎉 TOTP RESET SUCCESSFUL FOR:', user.email);
  console.log('======================================================');
  console.log('Manual Setup Key:', mfaSecret.base32);
  console.log('QR Code Page Saved At:', outputPath);
  console.log('\nNew Recovery Codes:');
  recovery.plainCodes.forEach(code => console.log(' -', code));
  console.log('======================================================\n');

  await mongoose.disconnect();
}

const targetEmail = process.argv[2] || 'mansikj07@gmail.com';
resetTotp(targetEmail).catch(err => {
  console.error('Error resetting TOTP:', err);
  process.exit(1);
});
