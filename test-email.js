require('dotenv').config();
const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT),
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

async function sendTestEmail() {
  try {
    console.log(`📤 Sending via ${process.env.SMTP_HOST}:${process.env.SMTP_PORT} as ${process.env.SMTP_USER}...`);
    const info = await transporter.sendMail({
      from: '"Form OS" <info@formos.online>',
      to: 'suradkaradarsh@gmail.com',
      subject: 'FormOS - Test Email',
      html: `
        <div style="font-family: Arial, sans-serif; color: #111827; line-height: 1.6; max-width: 500px; margin: auto;">
          <h2 style="color: #4f46e5;">FormOS Email Test ✅</h2>
          <p>This is a test email sent via <strong>Nodemailer + Brevo SMTP</strong>.</p>
          <p>If you received this, email delivery is working correctly.</p>
          <hr style="border: none; border-top: 1px solid #e5e7eb;" />
          <p style="color: #6b7280; font-size: 13px;">Sent from FormOS backend</p>
        </div>
      `,
    });
    console.log('✅ Email sent! Message ID:', info.messageId);
  } catch (err) {
    console.error('❌ Failed:', err.message);
  }
}

sendTestEmail();
