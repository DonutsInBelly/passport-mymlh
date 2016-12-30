// Module Dependencies
var util = require('util');
var OAuth2Strategy = require('passport-oauth2');
var InternalOAuthError = require('passport-oauth2').InternalOAuthError;

function Strategy(options, verify) {
  options = options || {};
  options.authorizationURL = options.authorizationURL || 'https://my.mlh.io/oauth/authorize';
  options.tokenURL = options.tokenURL || 'https://my.mlh.io/oauth/token';

  OAuth2Strategy.call(this, options, verify);
  this.name = 'mymlh';
  this._userProfileURL = options.userProfileURL || 'https://my.mlh.io/api/v1/user';

  var self = this;
  var _oauth2_getOAuthAccessToken = this._oauth2_getOAuthAccessToken;
  this._oauth2_getOAuthAccessToken = function (code, params, callback) {
    _oauth2_getOAuthAccessToken.call(self._oauth2, code, params, function (err, accessToken, refreshToken, params) {
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

Strategy.prototype.userProfile = function (accessToken, done) {
  this._oauth2.get(this._userProfileURL, accessToken, function (err, body, res) {
    if (err) { return done(new InternalOAuthError('failed to fetch user profile', err)); }

    try {
      var json = JSON.parse(body);
      console.log(json);
      var profile = { provider: 'mymlh' };
      profile.id = json.id;
      profile._raw = body;
      profile._json = json;

      done(null, profile);
    } catch(e) {
      done(e);
    }
  });
};

module.exports = Strategy;