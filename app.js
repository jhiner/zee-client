const express = require('express');
const path = require('path');
const favicon = require('serve-favicon');
const logger = require('morgan');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const renderFile = require('ejs').renderFile;
const passport = require('passport');
const OpenIDStrategy = require('passport-openidconnect');
const session = require('express-session');
const request = require('request');
require('dotenv').config()
const app = express();

const routes = require('./routes/index');

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.engine('.html', renderFile);

// uncomment after placing your favicon in /public
//app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: process.env.COOKIE_SECRET,
  resave: false,
  saveUninitialized: false,
  name: 'zee-client'
}));

// used to serialize the user for the session
passport.serializeUser(function(user, done) {
  done(null, user);
});

// used to deserialize the user
passport.deserializeUser(function(user, done) {
  return done(null, user);
});

passport.use(new OpenIDStrategy({
  issuer: process.env.ISSUER,
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: process.env.CALLBACK_URL,
  authorizationURL: process.env.ISSUER + '/authorize',
  userInfoURL: process.env.ISSUER + '/userinfo',
  tokenURL: process.env.ISSUER + '/token',
  passReqToCallback: true
},
function(req, iss, sub, profile, jwtClaims, accessToken, refreshToken, params, cb) {
  req.session.accessToken = accessToken;
  req.session.refreshToken = refreshToken;
  req.session.tokenParams = params;
  req.session.profile = profile._json;
  return cb(null, profile._json);
}));

app.use(passport.initialize());
app.use(passport.session());

app.use('/', routes);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  var err = new Error('Not Found');
  err.status = 404;
  next(err);
});

// error handlers

// development error handler
// will print stacktrace
if (app.get('env') === 'development') {
  app.use(function(err, req, res, next) {
    res.status(err.status || 500);
    res.render('error', {
      title: 'error',
      message: err.message,
      error: err
    });
  });
}

// production error handler
// no stacktraces leaked to user
app.use(function(err, req, res, next) {
  res.status(err.status || 500);
  res.render('error', {
    title: 'error',
    message: err.message,
    error: {}
  });
});


module.exports = app;
