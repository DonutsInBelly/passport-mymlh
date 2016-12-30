// Load modules.
var OAuth2Strategy = require('passport-oauth2')
  , util = require('util')
  , Profile = require('./profile')
  , InternalOAuthError = require('passport-oauth2').InternalOAuthError
  , APIError = require('./errors/apierror');

function Strategy(options, verify) {
  options = options || {};
  options.authorizationURL = options.authorizationURL || 'https://my.mlh.io/oauth/authorize';
  options.tokenURL = options.tokenURL || 'https://my.mlh.io/oauth/token';
  options.scopeSeparator = options.scopeSeparator || ',';
  options.customHeaders = options.customHeaders || {};

  OAuth2Strategy.call(this, options, verify);
  this.name = 'mymlh';
  this._userProfileURL = options.userProfileURL || 'https://my.mlh.io/api/v2/user.json';

  var self = this;
  var _oauth2_getOAuthAccessToken = this._oauth2.getOAuthAccessToken;
  this._oauth2.getOAuthAccessToken = function(code, params, callback) {
    _oauth2_getOAuthAccessToken.call(self._oauth2, code, params, function(err, accessToken, refreshToken, params) {
      if (err) { return callback(err); }
      if (!accessToken) {
        return callback({
          statusCode: 400,
          data: JSON.stringify(params)
        });
      }
      callback(null, accessToken, refreshToken, params);
    });
  }
}

// Inherit from `OAuth2Strategy`.
util.inherits(Strategy, OAuth2Strategy);

/**
 * Retrieve user profile from MyMLH.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `mlh`
 *   - `id`               the user's GitHub ID
 *   - `username`         the user's GitHub username
 *   - `displayName`      the user's full name
 *   - `profileUrl`       the URL of the profile for the user on GitHub
 *   - `emails`           the user's email addresses
 *
 * @param {string} accessToken
 * @param {function} done
 * @access protected
 */
Strategy.prototype.userProfile = function(accessToken, done) {
  var self = this;
  this._oauth2.get(this._userProfileURL, accessToken, function (err, body, res) {
    var json;

    if (err) {
      if (err.data) {
        try {
          json = JSON.parse(err.data);
        } catch (_) {}
      }

      if (json && json.message) {
        return done(new APIError(json.message));
      }
      return done(new InternalOAuthError('Failed to fetch user profile', err));
    }

    try {
      json = JSON.parse(body);
    } catch (ex) {
      return done(new Error('Failed to parse user profile'));
    }

    var profile = Profile.parse(json);
    profile.provider  = 'mlh';
    profile._raw = body;
    profile._json = json;


    if (self._scope && self._scope.indexOf('user:email') !== -1) {
      self._oauth2._request('GET', self._userProfileURL + '/emails', { 'Accept': 'application/json' }, '', accessToken, function(err, body, res) {
        if (err) {
          // If the attempt to fetch email addresses fails, return the profile
          // information that was obtained.
          return done(null, profile);
        }

        var json;
        try {
          json = JSON.parse(body);
        } catch (_) {
          // If the attempt to parse email addresses fails, return the profile
          // information that was obtained.
          return done(null, profile);
        }


        if (!json.length) {
          return done(null, profile);
        }

        profile.emails = profile.emails || [];
        var publicEmail = profile.emails[0];

        (json).forEach(function(email) {
          if (publicEmail && publicEmail.value == email.email) {
            profile.emails[0].primary = email.primary;
            profile.emails[0].verified = email.verified;
          } else {
            profile.emails.push({ value: email.email, primary: email.primary, verified: email.verified })
          }
        });
        done(null, profile);
      });
    }
    else {
      done(null, profile);
    }
  });
}


// Expose constructor.
module.exports = Strategy;
