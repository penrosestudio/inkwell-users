var mongoose = require('mongoose'),
    bcrypt = require('bcrypt'),
    SALT_WORK_FACTOR = 10;

var userSchema = mongoose.Schema({
  email: {
    type: String,
    unique: true
  },
  password: {
    type: String
  },
  role: String
});

// Bcrypt middleware
userSchema.pre('save', function(next) {
  var user = this;
  if(!user.isModified('password')) return next();
  bcrypt.genSalt(SALT_WORK_FACTOR, function(err, salt) {
    if(err) return next(err);    
    bcrypt.hash(user.password, salt, function(err, hash) {
      if(err) return next(err);
      user.password = hash;
      next();
    });
  });
});

// Simple route middleware to ensure user is authenticated.
//   Use this route middleware on any resource that needs to be protected.  If
//   the request is authenticated (typically via a persistent login session),
//   the request will proceed.  Otherwise, the user will be redirected to the
//   login page.
// Set here so accessible via export for use in other modules
userSchema.statics.ensureAuthenticated = function(req, res, next) {
  if (req.isAuthenticated()) { return next(); }
  req.session.redirect_url = req.url;
  res.redirect('/login');
};
userSchema.statics.ensureRoleAuthenticated = function(role) {
  return function(req, res, next) {
    if (!req.user || req.user.role!=='admin' && req.user.role!==role) { // always allow 'admin' role to see pages
      //return next(new Error("Permission denied"));
      return res.send(403);
    }
    userSchema.statics.ensureAuthenticated.call(this, req, res, next);  
  };
};
userSchema.statics.getCurrentUser = function(req) {
  var username;
  if(req && req.user) {
    username = req.user.email;
  }
  return username;
};
// Password verification
userSchema.methods.comparePassword = function(candidatePassword, cb) {
  // allow for test users with hard-coded password in the database
  if(this.password==='password' && candidatePassword==='password') {
      return cb(null, true);
  }
  if(!this.password) {
      return cb(new Error('No password set for this user'));
  }
  bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
    if(err) return cb(err);
    cb(null, isMatch);
  });
};
userSchema.methods.getRole = function() {
  return this.role;
};

var User = mongoose.model('User', userSchema);

module.exports = User;