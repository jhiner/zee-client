const express = require('express');
const router = express.Router();
const ensureLoggedIn = require('connect-ensure-login').ensureLoggedIn;
const passport = require('passport');
const _ = require('lodash');

// home page
router.get('/', function(req, res, next) {
  res.render('index', { title: 'Zee Demo Client' });
});

// protected page that will use ensureLoggedIn middleware to direct to /login page if not logged in
router.get('/protected', ensureLoggedIn({ 
  redirectTo: '/login',
  setReturnTo: '/protected'
}), function(req, res) {
  // decode id token payload
  let jwtPayload = req.session.tokenParams.id_token.split('.')[1];
  let decodedPayload = Buffer.from(jwtPayload, 'base64');

  res.render('protected', {
    title: 'Protected Page',
    user: req.user, 
    accessToken: req.session.accessToken,
    refreshToken: req.session.refreshToken,
    tokenParams: req.session.tokenParams,
    tokenResponse: _.pick(req.session.tokenParams, ['expires_in', 'scope']),
    userInfoResponse: req.session.profile,
    decodedIdTokenPayload: decodedPayload
  });
});

router.get('/login', passport.authenticate('openidconnect', { 
  scope: 'profile email offline_access',
  state: true
}));

router.post('/login', function(req, res, next) {
  
  let scope = req.body.scope;
  let prompt = req.body.prompt;

  if (prompt === 'empty') {
    prompt = undefined;
  }
  
  return passport.authenticate('openidconnect', {
    scope: scope,
    prompt: prompt,
    state: true
  })(req, res, next);
});

router.get('/callback',
  passport.authenticate('openidconnect', { failWithError: true }),
  function(req, res) {
    // Successful authentication, redirect to protected page
    res.redirect('/protected');
});

router.get('/logout', function(req, res, next) {
  req.logout();
  res.redirect('/');
});

router.post('/logout', function(req, res, next) {
  console.log('POST LOGOUT');
  if (req.body.federated === 'on') {
    // initiate logout at OP
    // TODO env var
    req.logout(); // per the spec, RP should logout first, then logout at OP
    return res.redirect(`${process.env.ISSUER}/oidc/logout?post_logout_redirect_uri=${process.env.POST_LOGOUT_REDIRECT_URI}`);
  }

  return res.redirect('/logout');
});

module.exports = router;