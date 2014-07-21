/*
 * User controller
 *
 * Handles login, logout, forgot password and account activation routes
 */
var fs = require('fs'),
    path = require('path'),
    session = require('express-session'),
    flash = require('connect-flash'),
    passport = require('passport'),
    LocalStrategy = require('passport-local').Strategy,
    mandrill = require('mandrill-api/mandrill'),
    mandrill_client = new mandrill.Mandrill(process.env.MANDRILL_APIKEY),
    User = require('./user'),
    productionHost = 'http://www.myhost.com', // TO-DO: get this out of this controller to make it generic; for now, set this here
    developmentHost = 'http://localhost:5000', // this one too
    ensureAuthenticated = User.ensureAuthenticated,
    active_reset_tokens = {};

module.exports.controller = function(app) {

  setup(app);

  // Handle login and logout

  app.get('/login', function(req, res){
    var json = {};
    json.message = req.flash('error');
    res.render('login/index', json);
  });
  
  app.post('/login', function(req, res, next) {
    passport.authenticate('local', function(err, user, info) {
      console.log('authenticated user',user);
      //if (err) { return next(err); }
      if(err) {
          req.flash('error', err.message);
          return res.redirect('/login');
      }
      if (!user) {
        req.flash('error', info.message || 'Invalid login');
        return res.redirect('/login');
      }
      req.login(user, function(err) {
        if (err) { return next(err); }
        var redirectPath = req.session.redirect_url;
        delete req.session.redirect_url;
        return res.redirect(redirectPath);
      });
    })(req, res, next);
  });
  
  app.get('/logout', function(req, res){
    req.logout();
    res.redirect('/login');
  });
  
  // Handle password reset
  
  app.get('/forgot-password', function(req, res) {
    res.render('login/forgot-password', {
      title: 'Forgotten password?',
      message: req.flash('message'),
      error: req.flash('error')
    });
  });
    
  app.post('/forgot-password', function(req, res) {
    var email = req.body.email;
    User.findOne({email: email}, function(err, user) {
      if(!user) {
        req.flash('error', 'No account found with that email address');
        return res.redirect('/forgot-password');
      }
      var token = create_token();
      active_reset_tokens[token] = user.id;
      send_user_password_reset_email(email, token, function(err) {
        req.flash('message', 'Please check your email for a link to reset your password');
        res.redirect('forgot-password');
      });
    });
  });

  app.get('/reset-password/:token?', function(req, res) {
    res.render('reset-password', {
      title: 'Reset your password',
      token: req.params.token,
      error: req.flash('error'),
      message: req.flash('message')
    });
  });

  app.post('/reset-password', function(req, res) {
    var token = req.body.token;
    // validate password
    var password = req.body.password;
    var confirm = req.body.confirm;
    if(!password || !confirm || password!==confirm) {
      // not valid, respond with error message
      req.flash('error', 'Both password fields need to be the same, please try again');
      return res.redirect('/reset-password/'+token);
    }
    var user_account_id = active_reset_tokens[token];
    if(user_account_id) {
      User.findById(user_account_id, function(err, user) {
        if(user) {
          // go ahead and update the password
          user.password = password;
          user.save(function(err) {
            // delete token so it can't be used again
            delete active_reset_tokens[token];
            req.flash('message', 'Password successfully changed - <a href="/login">click here to login</a>');
            return res.redirect('/reset-password');
          });
        }
      });      
    } else {
      req.flash('error', 'Token not valid');
      return res.redirect('/reset-password');  
    }
  });

  // Handle account activation

  app.get('/activate', ensureAuthenticated, function(req, res) {
    var accountID = "";
    res.render('login/activate-account', {
      title: 'Activate Account',
      accountID: accountID
    });
  });
  
  app.post('/activate', ensureAuthenticated, function(req, res) {
    // TO-DO: activate the account
    res.redirect('/', { // TO-DO: make this correct
      title: 'Home'
    });
  });

};

function setup(app) {
  // Set up user-specific app config

  // set up session handling
  app.use(session({
    secret: 'jabbajabbajabba',
    cookie: {
      maxAge: 6000000
    }
  }));
  // add little hack to update cookie expiry on a request
  // see http://stackoverflow.com/questions/14464873/expressjs-session-expiring-despite-activity
  app.use(function (req, res, next) {
      if ('HEAD' == req.method || 'OPTIONS' == req.method) return next();
      // break session hash / force express to spit out a new cookie once per second at most
      req.session._garbage = Date();
      req.session.touch();
      next();
  });

  // add session-based flash message
  app.use(flash());
  
  // initialise passport
  app.use(passport.initialize());
  app.use(passport.session());
  
  // Passport session setup.
  //   To support persistent login sessions, Passport needs to be able to
  //   serialize users into and deserialize users out of the session.  Typically,
  //   this will be as simple as storing the user ID when serializing, and finding
  //   the user by ID when deserializing.
  passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function (err, user) {
      done(err, user);
    });
  });
  
  // Set up authentication
  passport.use(new LocalStrategy({
      usernameField: 'email',
      passwordField: 'password'
    },
    function(email, password, done) {
      email = email.trim();
      password = password.trim();
      User.findOne({ email: email }, function(err, user) {
        if (err) { return done(err); }
        if (!user) {
          return done(null, false, { message: 'Incorrect email' });
        }
        // look up the hash of the password for other users
        user.comparePassword(password, function(err, isMatch) {
          if (err) return done(err);
          if(isMatch) {
            return done(null, user);
          } else {
            return done(null, false, { message: 'Incorrect password' });
          }
        });
      });
    }
  ));
}

function send_user_password_reset_email(email, token, callback) {
  var host_name = process.env.PRODUCTION ? productionHost : developmentHost,
    url = host_name + "/reset-password/" + token,
    email_body = 'Follow this link to reset your password. If you did not request a password reset, please ignore this email.<br><br><a href="'+url+'">'+url+'</a>',
    messageObj = {
      html: email_body,
      subject: 'Password reset',
      from_email: 'no-reply@myhost.com',
      to: [{
        email: email
      }]
    },
    emailObj;
  mandrill_client.messages.send({message: messageObj}, function(result) {
    return callback();
  }, function(e) {
    // Mandrill returns the error as an object with name and message keys
    return callback(e);
  });
}

function create_token() {
  // create a token from random 4-digit hexadecimal strings
  var s4 = function() {
      return (((1+Math.random())*0x10000)|0).toString(16).substring(1);    
    };
  return s4()+'-'+s4();
}