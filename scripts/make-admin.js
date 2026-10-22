// Creates or updates a staff account for the admin console.
//
//   node scripts/make-admin.js <email> [admin|superadmin|user|keep] [--generate]
//
//   role      defaults to superadmin. "user" removes staff access and the console password.
//             "keep" leaves the role alone (use it to change the password later).
//   password  asked for with a hidden prompt (twice). Set ADMIN_PASSWORD in the environment
//             for scripted use, or pass --generate to create a strong one and print it once.
//
// The password is never taken from the command line, so it stays out of shell history.
// The account must already exist (signed up, email verified, authenticator enrolled).
const path = require('path');
const crypto = require('crypto');
const readline = require('readline');
require('dotenv').config({ path: path.join(__dirname, '../.env') });
const mongoose = require('mongoose');
const User = require('../models/User');
const { findUserByEmail } = require('./../services/accountService');
const { hashAdminPassword, validateAdminPassword, ADMIN_PASSWORD_MIN } = require('../services/securityService');

const ask = (question, { hidden = false } = {}) => new Promise((resolve) => {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
  if (hidden) {
    rl._writeToOutput = (text) => { if (text.includes(question)) rl.output.write(text); else rl.output.write('*'.repeat(text.replace(/[\r\n]/g, '').length)); };
  }
  rl.question(question, (answer) => { rl.close(); if (hidden) process.stdout.write('\n'); resolve(answer); });
});

const generatePassword = () => {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  const bytes = crypto.randomBytes(20);
  let out = '';
  for (let i = 0; i < 20; i += 1) out += alphabet[bytes[i] % alphabet.length];
  return `${out.slice(0, 5)}-${out.slice(5, 10)}-${out.slice(10, 15)}-${out.slice(15)}`;
};

(async () => {
  const args = process.argv.slice(2).filter((a) => !a.startsWith('--'));
  const generate = process.argv.includes('--generate');
  const [email, role = 'superadmin'] = args;

  if (!email || !['user', 'admin', 'superadmin', 'keep'].includes(role)) {
    console.error('Usage: node scripts/make-admin.js <email> [admin|superadmin|user|keep] [--generate]');
    process.exit(1);
  }

  await mongoose.connect(process.env.MONGODB_URI);
  const user = await findUserByEmail(email);
  if (!user) {
    console.error(`No account found for ${email}. Sign up in the FormOS app first.`);
    await mongoose.disconnect();
    process.exit(1);
  }

  const update = {};
  const effectiveRole = role === 'keep' ? user.role : role;
  if (role !== 'keep') update.role = role;

  if (effectiveRole === 'user') {
    update.adminPasswordHash = null;
    update.adminPasswordSetAt = null;
    update.adminFailedLogins = 0;
    update.adminLockedUntil = null;
  } else {
    let password = process.env.ADMIN_PASSWORD;
    let shown = false;
    if (generate) {
      password = generatePassword();
      shown = true;
    } else if (!password) {
      if (!process.stdin.isTTY) {
        console.error('No terminal to ask for a password. Set ADMIN_PASSWORD in the environment, or use --generate.');
        await mongoose.disconnect();
        process.exit(1);
      }
      for (;;) {
        password = await ask(`New admin console password for ${user.email} (min ${ADMIN_PASSWORD_MIN} characters): `, { hidden: true });
        const problem = validateAdminPassword(password, user.email);
        if (problem) { console.error(problem); continue; }
        const again = await ask('Type it again: ', { hidden: true });
        if (again !== password) { console.error('The two entries did not match. Try again.'); continue; }
        break;
      }
    }
    const problem = validateAdminPassword(password, user.email);
    if (problem) {
      console.error(problem);
      await mongoose.disconnect();
      process.exit(1);
    }
    update.adminPasswordHash = await hashAdminPassword(password);
    update.adminPasswordSetAt = new Date();
    update.adminFailedLogins = 0;
    update.adminLockedUntil = null;
    if (shown) {
      console.log('\nGenerated password (shown once, store it in a password manager):\n');
      console.log(`  ${password}\n`);
    }
  }

  await User.updateOne({ _id: user._id }, { $set: update });
  console.log(`${user.email} is now: ${effectiveRole}${effectiveRole === 'user' ? '' : ' (admin console password set)'}`);
  if (effectiveRole !== 'user') {
    console.log(process.env.ADMIN_REQUIRE_MFA === 'true'
      ? 'Sign in at /admin with that email and password, then your authenticator code.'
      : 'Sign in at /admin with that email and password.');
  }
  await mongoose.disconnect();
})().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
