const path = require('path');
const nodemailer = require('nodemailer');

// Create Nodemailer transporter with Brevo SMTP
const createTransporter = () => {
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'smtp-relay.brevo.com',
    port: parseInt(process.env.SMTP_PORT || '587'),
    secure: false,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });
};

// ─── Layout ──────────────────────────────────────────────────────────────────
// Same look as the site: ink, steel blue, brass and mist, thin ink borders, 14px cards, 10px controls.
// Email clients ignore most CSS, so this is tables with inline styles and system fonts only.
const INK = '#2c3947';
const MUTED = '#566272';
const BRASS = '#c2a56d';
const MIST = '#eef1f5';
const FONT = "'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, 'Helvetica Neue', Arial, sans-serif";

const LOGO_CID = 'formos-logo@formos';
const logoAttachment = {
  filename: 'formos-logo.png',
  path: path.join(__dirname, '..', 'assets', 'email-logo.png'),
  cid: LOGO_CID,
};

const escapeHtml = (value) =>
  String(value ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// One layout for every message: logo, a title, a short line, the code, how long it lasts, and a note.
const renderCodeEmail = ({ preheader, title, name, intro, code, expiresInMinutes, note }) => {
  const safeName = escapeHtml(name || 'there');
  const spacedCode = escapeHtml(code);
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light">
  <title>${escapeHtml(title)}</title>
</head>
<body style="margin:0;padding:0;background:${MIST};">
  <div style="display:none;max-height:0;overflow:hidden;opacity:0;color:${MIST};">${escapeHtml(preheader)}</div>
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:${MIST};">
    <tr>
      <td align="center" style="padding:32px 16px;">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:520px;">
          <tr>
            <td style="padding:0 4px 16px;">
              <table role="presentation" cellpadding="0" cellspacing="0">
                <tr>
                  <td style="vertical-align:middle;padding-right:10px;"><img src="cid:${LOGO_CID}" width="32" height="32" alt="" style="display:block;border:0;"></td>
                  <td style="vertical-align:middle;font-family:${FONT};font-size:22px;font-weight:800;letter-spacing:-0.5px;color:${INK};">FormOS</td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td style="background:#ffffff;border:1.5px solid ${INK};border-radius:14px;padding:32px 28px;font-family:${FONT};color:${INK};">
              <h1 style="margin:0 0 14px;font-size:26px;line-height:1.15;font-weight:800;letter-spacing:-0.8px;color:${INK};">${escapeHtml(title)}</h1>
              <p style="margin:0 0 8px;font-size:16px;line-height:1.55;color:${INK};">Hello ${safeName},</p>
              <p style="margin:0 0 22px;font-size:16px;line-height:1.55;color:${INK};">${escapeHtml(intro)}</p>

              <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td align="center" style="background:${MIST};border:1.5px solid ${INK};border-radius:10px;padding:18px 12px;">
                    <span style="font-family:'SFMono-Regular',Menlo,Consolas,'Courier New',monospace;font-size:32px;line-height:1;font-weight:700;letter-spacing:10px;padding-left:10px;color:${INK};">${spacedCode}</span>
                  </td>
                </tr>
                <tr>
                  <td style="height:4px;background:${BRASS};border-radius:0 0 10px 10px;font-size:0;line-height:0;">&nbsp;</td>
                </tr>
              </table>

              <p style="margin:18px 0 0;font-size:14px;line-height:1.5;font-weight:600;color:${INK};">This code expires in ${escapeHtml(expiresInMinutes)} minutes. It works once.</p>
              <p style="margin:18px 0 0;padding-top:18px;border-top:1px solid #d5dbe2;font-size:14px;line-height:1.55;color:${MUTED};">${note}</p>
            </td>
          </tr>
          <tr>
            <td style="padding:18px 4px 0;font-family:${FONT};font-size:12px;line-height:1.5;color:${MUTED};">
              FormOS keeps your documents in a private vault. We never ask for your PIN, password or codes by email, phone or chat.
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;
};

const renderCodeText = ({ title, name, intro, code, expiresInMinutes, noteText }) =>
  [`${title}`, '', `Hello ${name || 'there'},`, '', intro, '', `Your code: ${code}`, `It expires in ${expiresInMinutes} minutes and works once.`, '', noteText, '', 'FormOS never asks for your PIN, password or codes by email, phone or chat.'].join('\n');

const sendCodeEmail = async ({ email, subject, parts }) => {
  const transporter = createTransporter();
  await transporter.sendMail({
    from: '"FormOS" <info@formos.online>',
    to: email,
    subject,
    html: renderCodeEmail(parts),
    text: renderCodeText(parts),
    attachments: [logoAttachment],
  });
};

// ─── Messages ────────────────────────────────────────────────────────────────
const sendVerificationEmail = async ({ email, name, code, expiresInMinutes = 15 }) => {
  try {
    await sendCodeEmail({
      email,
      subject: 'Your FormOS verification code',
      parts: {
        preheader: `Your FormOS code is ${code}. It expires in ${expiresInMinutes} minutes.`,
        title: 'Your verification code',
        name,
        intro: 'Enter this code in FormOS to confirm your email and continue.',
        code,
        expiresInMinutes,
        note: 'Did not ask for this? You can ignore this email. Nothing changes on your account until a code is entered.',
        noteText: 'Did not ask for this? You can ignore this email. Nothing changes on your account until a code is entered.',
      },
    });

    console.log(`Email sent to ${email} via Brevo SMTP`);
  } catch (error) {
    console.error('Nodemailer/Brevo failed:', error.message);

    // Fallback to Development Mode: Log OTP to console
    console.log('\n========================================');
    console.log('VERIFICATION EMAIL (Development Mode - Fallback)');
    console.log('========================================');
    console.log(`To: ${email}`);
    console.log(`Name: ${name}`);
    console.log(`Code: ${code}`);
    console.log(`Expires in: ${expiresInMinutes} minutes`);
    console.log('========================================\n');

    // Don't throw error - allow registration to continue with console OTP
    console.log('Email sending failed, but the code is logged above for development');
  }
};

const sendPasswordResetEmail = async ({ email, name, code, expiresInMinutes = 15 }) => {
  try {
    await sendCodeEmail({
      email,
      subject: 'Reset your FormOS PIN',
      parts: {
        preheader: `Your FormOS reset code is ${code}. It expires in ${expiresInMinutes} minutes.`,
        title: 'Reset your PIN',
        name,
        intro: 'We got a request to reset your PIN. Enter this code in FormOS to choose a new one.',
        code,
        expiresInMinutes,
        note: '<strong style="color:#2c3947;">Did not ask for this?</strong> Ignore this email and your PIN stays as it is. If you keep getting these, sign in and review your security settings.',
        noteText: 'Did not ask for this? Ignore this email and your PIN stays as it is. If you keep getting these, sign in and review your security settings.',
      },
    });

    console.log(`Password reset email sent to ${email} via Brevo SMTP`);
  } catch (error) {
    console.error('Nodemailer/Brevo failed:', error.message);

    // Fallback to Development Mode: Log OTP to console
    console.log('\n========================================');
    console.log('PASSWORD RESET EMAIL (Development Mode - Fallback)');
    console.log('========================================');
    console.log(`To: ${email}`);
    console.log(`Name: ${name}`);
    console.log(`Reset Code: ${code}`);
    console.log(`Expires in: ${expiresInMinutes} minutes`);
    console.log('========================================\n');

    // Don't throw error - allow reset to continue with console OTP
    console.log('Email sending failed, but the reset code is logged above for development');
  }
};

module.exports = {
  sendVerificationEmail,
  sendPasswordResetEmail,
  // exported so the layout can be previewed without sending mail
  renderCodeEmail,
};
