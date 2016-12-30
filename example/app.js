var express       = require('express');
var passport      = require('passport');
var util          = require('util');
var MyMLHStrategy = require('passport-mymlh').Strategy;
var session       = require('express-session');
var cookieParser  = require('cookie-parser');
var bodyParser    = require('body-parser');
var morgan        = require('morgan');

// Config to hold Client ID and Secret
const config      = require('./config.js');

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(obj, done)) {
  
}
