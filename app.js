var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
require('dotenv').config();


var indexRouter = require('./routes/index');
var usersRouter = require('./routes/users');

var app = express();

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use('/', indexRouter);
app.use('/users', usersRouter);

// Add session support
app.use(session({  
    secret: process.env.SESSION_SECRET || 'default_session_secret',
    resave: false,
    saveUninitialized: false,
  }));
  app.use(passport.initialize());  
  app.use(passport.session());
  
  passport.serializeUser((user, done) => {  
    done(null, user);
  });
  
  passport.deserializeUser((userDataFromCookie, done) => {  
    done(null, userDataFromCookie);
  });
  
  // Checks if a user is logged in
  const accessProtectionMiddleware = (req, res, next) => {  
    if (req.isAuthenticated()) {
      
      next();
    } else {
      res.status(403).json({
        message: 'must be logged in to continue',
      });
    }
  };
  passport.use(new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_OAUTH_TEST_APP_CLIENT_ID,
      clientSecret: process.env.GOOGLE_OAUTH_TEST_APP_CLIENT_SECRET,
      callbackURL: 'https://sheltered-woodland-76765.herokuapp.com/auth/google/callback',
      scope: ['email'],
    },
    // This is a "verify" function required by all Passport strategies
    (accessToken, refreshToken, profile, cb) => {
      console.log('Our user authenticated with Google, and Google sent us back this profile info identifying the authenticated user:', profile);
      return cb(null, profile);
    },
  ));
  
  // Serve a test API endpoint
  /* app.get('/test', (req, res) => {
    res.send('Your api is working!');
  }); */
  
  //app.get('/auth/google', passport.authenticate('google'));  
  
  // Create API endpoints
  app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/', session: false }),
    (req, res) => {
      console.log('wooo we authenticated, here is our user object:', req.user);
      res.json(req.user);
    }
  );
  
  
  
  // A secret endpoint accessible only to logged-in users
  app.get('/protected', accessProtectionMiddleware, (req, res) => {
    res.json({
      message: 'You have accessed the protected endpoint!',
      yourUserInfo: req.user,
    });
  });

module.exports = app;
