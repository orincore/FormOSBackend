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

const sendVerificationEmail = async ({ email, name, code, expiresInMinutes = 15 }) => {
  const subject = 'Verify your FormOS account';
  const safeName = name || 'there';
  const html = `
    <div style="font-family: Arial, sans-serif; color: #111827; line-height: 1.6;">
      <h2 style="margin-bottom: 12px;">Verify your FormOS account</h2>
      <p>Hello ${safeName},</p>
      <p>Use the following one-time verification code to continue your registration:</p>
      <div style="font-size: 28px; font-weight: 700; letter-spacing: 8px; margin: 18px 0; color: #4f46e5;">
        ${code}
      </div>
      <p>This code expires in ${expiresInMinutes} minutes.</p>
      <p>If you did not request this, you can ignore this email.</p>
    </div>
  `;

  try {
    // Try sending with Nodemailer + Brevo SMTP
    const transporter = createTransporter();
    
    await transporter.sendMail({
      from: '"Form OS" <info@formos.online>',
      to: email,
      subject: subject,
      html: html,
    });

    console.log(`✅ Email sent successfully to ${email} via Brevo SMTP`);
  } catch (error) {
    console.error('❌ Nodemailer/Brevo failed:', error.message);
    
    // Fallback to Development Mode: Log OTP to console
    console.log('\n========================================');
    console.log('📧 VERIFICATION EMAIL (Development Mode - Fallback)');
    console.log('========================================');
    console.log(`To: ${email}`);
    console.log(`Name: ${name}`);
    console.log(`Code: ${code}`);
    console.log(`Expires in: ${expiresInMinutes} minutes`);
    console.log('========================================\n');
    
    // Don't throw error - allow registration to continue with console OTP
    console.log('⚠️  Email sending failed, but OTP is logged above for development');
  }
};

const sendPasswordResetEmail = async ({ email, name, code, expiresInMinutes = 15 }) => {
  const subject = 'Reset your FormOS PIN';
  const safeName = name || 'there';
  const html = `
    <div style="font-family: Arial, sans-serif; color: #111827; line-height: 1.6;">
      <h2 style="margin-bottom: 12px;">Reset your FormOS PIN</h2>
      <p>Hello ${safeName},</p>
      <p>We received a request to reset your PIN. Use the following code to continue:</p>
      <div style="font-size: 28px; font-weight: 700; letter-spacing: 8px; margin: 18px 0; color: #4f46e5;">
        ${code}
      </div>
      <p>This code expires in ${expiresInMinutes} minutes.</p>
      <p><strong>If you didn't request this, please ignore this email.</strong> Your account is secure.</p>
      <p style="margin-top: 24px; color: #6b7280; font-size: 14px;">
        For security reasons, we never send PINs via email. This code is only for verification.
      </p>
    </div>
  `;

  try {
    // Try sending with Nodemailer + Brevo SMTP
    const transporter = createTransporter();
    
    await transporter.sendMail({
      from: '"Form OS" <info@formos.online>',
      to: email,
      subject: subject,
      html: html,
    });

    console.log(`✅ Password reset email sent successfully to ${email} via Brevo SMTP`);
  } catch (error) {
    console.error('❌ Nodemailer/Brevo failed:', error.message);
    
    // Fallback to Development Mode: Log OTP to console
    console.log('\n========================================');
    console.log('🔒 PASSWORD RESET EMAIL (Development Mode - Fallback)');
    console.log('========================================');
    console.log(`To: ${email}`);
    console.log(`Name: ${name}`);
    console.log(`Reset Code: ${code}`);
    console.log(`Expires in: ${expiresInMinutes} minutes`);
    console.log('========================================\n');
    
    // Don't throw error - allow reset to continue with console OTP
    console.log('⚠️  Email sending failed, but reset code is logged above for development');
  }
};

module.exports = {
  sendVerificationEmail,
  sendPasswordResetEmail,
};
