const passport = require('passport');
const { Strategy: GoogleStrategy } = require('passport-google-oauth20');
const { Strategy: GitHubStrategy } = require('passport-github2');
const { resolveGithubVerifiedEmail } = require('../services/oauthService');

const providerConfig = {
  google: !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET && process.env.GOOGLE_CALLBACK_URL),
  github: !!(process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET && process.env.GITHUB_CALLBACK_URL),
};

if (providerConfig.google) {
  passport.use('google', new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL,
    passReqToCallback: true,
  }, async (req, accessToken, refreshToken, profile, done) => {
    try {
      const primaryEmail = profile.emails?.[0]?.value?.toLowerCase() || null;
      return done(null, {
        provider: 'google',
        providerId: profile.id,
        email: primaryEmail,
        emailVerified: profile._json?.email_verified === true || profile._json?.email_verified === 'true' || profile.emails?.[0]?.verified === true || profile.emails?.[0]?.verified === 'true',
        name: profile.displayName || primaryEmail || 'Google User',
        avatarUrl: profile.photos?.[0]?.value || null,
        profileUrl: null,
        username: null,
      });
    } catch (error) {
      return done(error);
    }
  }));
}

if (providerConfig.github) {
  passport.use('github', new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: process.env.GITHUB_CALLBACK_URL,
    scope: ['read:user', 'user:email'],
    passReqToCallback: true,
  }, async (req, accessToken, refreshToken, profile, done) => {
    try {
      const verifiedEmail = await resolveGithubVerifiedEmail(accessToken);
      return done(null, {
        provider: 'github',
        providerId: String(profile.id),
        email: verifiedEmail?.email?.toLowerCase() || null,
        emailVerified: !!verifiedEmail?.verified,
        name: profile.displayName || profile.username || 'GitHub User',
        avatarUrl: profile.photos?.[0]?.value || null,
        profileUrl: profile.profileUrl || null,
        username: profile.username || null,
      });
    } catch (error) {
      return done(error);
    }
  }));
}

const isProviderConfigured = (provider) => !!providerConfig[provider];

module.exports = {
  isProviderConfigured,
  passport,
};
