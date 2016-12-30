// Module Dependencies
var util = require('util');
var OAuth2Strategy = require('passport-oauth2');
var InternalOAuthError = require('passport-oauth2').InternalOAuthError;

function Strategy(options, verify) {
  options = options || {};
  options.authorizationURL = options.authorizationURL || 'https://my.mlh.io/oauth/authorize';
  options.tokenURL = options.tokenURL || 'https://my.mlh.io/oauth/token';
  options.scopeSeparator = options.scopeSeparator || '+';
  options.customHeaders = options.customHeaders || {};

  if (!options.customHeaders['User-Agent']) {
    options.customHeaders['User-Agent'] = options.userAgent || 'passport-mymlh';
  }

  OAuth2Strategy.call(this, options, verify);
  this.name = 'mymlh';
  this._userProfileURL = options.userProfileURL || 'https://my.mlh.io/api/v2/user';

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

util.inherits(Strategy, OAuth2Strategy);

Strategy.prototype.userProfile = function (accessToken, done) {
  this._oauth2.get(this._userProfileURL, accessToken, function (err, body, res) {
    if (err) { return done(new InternalOAuthError('failed to fetch user profile', err)); }

    try {
      var json = JSON.parse(body);
      console.log(json);
      var profile = { provider: 'mymlh' };
      profile.id = json.data.id;
      profile.email = json.data.email;
      profile.created_at = json.data.created_at;
      profile.updated_at = json.data.updated_at;
      profile.first_name = json.data.first_name;
      profile.last_name = json.data.last_name;
      profile.major = json.data.major;
      profile.shirt_size = json.data.shirt_size;
      profile.dietary_restrictions = json.data.dietary_restrictions;
      profile.special_needs = json.data.special_needs;
      profile.date_of_birth = json.data.date_of_birth;
      profile.gender = json.data.gender;
      profile.phone_number = json.data.phone_number;
      profile.level_of_study = json.data.level_of_study;
      profile.school = json.data.school;
      profile._data = json.data;
      profile._raw = body;
      profile._json = json;

      done(null, profile);
    } catch(e) {
      done(e);
    }
  });
};

module.exports = Strategy;
