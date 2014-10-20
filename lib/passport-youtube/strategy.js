/**
 * Module dependencies.
 */
var util = require('util')
  , OAuth2Strategy = require('passport-oauth').OAuth2Strategy
  , InternalOAuthError = require('passport-oauth').InternalOAuthError;


/**
 * `Strategy` constructor.
 *
 * Youtube authentication strategy authenticates requests using the OAuth 2.0 protocol.
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  options = options || {};
  options.authorizationURL = options.authorizationURL || 'https://accounts.google.com/o/oauth2/auth';
  options.tokenURL = options.tokenURL || 'https://accounts.google.com/o/oauth2/token';
  options.scopeSeparator = options.scopeSeparator || ',';

  OAuth2Strategy.call(this, options, verify);
  this.name = 'youtube';
  this._profileURL = options.profileURL || 'https://gdata.youtube.com/feeds/api/users/default?alt=json';
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);

/**
 * Retrieve user profile from Youtube.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `youtube`
 *   - `id`               the user's Google Plus user ID
 *   - `username`         the user's Youtube username
 *   - `displayName`      the user's full name
 *   - `name.familyName`  the user's last name
 *   - `name.givenName`   the user's first name
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function(accessToken, done) {
  var url = this._profileURL;

  this._oauth2.getProtectedResource(url, accessToken, function (err, body, res) {

    if (err) { return done(new InternalOAuthError('failed to fetch user profile', err)); }

    try {
      var json = JSON.parse(body);

      var youtubeProfile = json.entry;

      var profile = { provider: 'youtube' };
      var id = youtubeProfile['id']['$t'].replace(/http:\/\/gdata.youtube.com\/feeds\/api\/users\//g, '');

      profile.id = id;
      profile.channelId = 'UC' + id;
      profile.displayName = youtubeProfile['title']['$t'];

      profile.published = ( youtubeProfile['published'] && youtubeProfile['published']['$t'] ) ? youtubeProfile['published']['$t'] : '',
      profile.updated   = ( youtubeProfile['updated'] && youtubeProfile['updated']['$t'] ) ? youtubeProfile['updated']['$t'] : '',
      //category : [ [Object] ],
      profile.title     = ( youtubeProfile['title'] && youtubeProfile['title']['$t'] ) ? youtubeProfile['title']['$t'] : '';
      profile.content   = ( youtubeProfile['content'] && youtubeProfile['content']['$t'] ) ? youtubeProfile['content']['$t'] : '';
      //link    = [ [Object], [Object], [Object] ],
      //author  = [ [Object] ],
      //'gd$feedLink'= [ [Object], [Object], [Object], [Object], [Object], [Object] ],

      profile.googlePlusUserId = ( youtubeProfile['yt$googlePlusUserId'] && youtubeProfile['yt$googlePlusUserId']['$t'] ) ? youtubeProfile['yt$googlePlusUserId']['$t'] : '';
      profile.location         = ( youtubeProfile['yt$location'] && youtubeProfile['yt$location']['$t'])  ? youtubeProfile['yt$location']['$t'] : '';

      //'yt$maxUploadDuration'= { seconds: '930' },
      profile.statistics = youtubeProfile['yt$statistics'] || {};

      //'media$thumbnail'= { url: 'https://yt3.ggpht.com/-1ut-vqtPh5U/AAAAAAAAAAI/AAAAAAAAAAA/e9GvBgVO6Us/s88-c-k-no/photo.jpg' },

      profile.username   = ( youtubeProfile['yt$username'] && youtubeProfile['yt$username']['$t'] ) ? youtubeProfile['yt$username']['$t'] : '';



      if(youtubeProfile['yt$lastName'] && youtubeProfile['yt$firstName']) {
        profile.name = { familyName: youtubeProfile['yt$lastName']['$t'], givenName: youtubeProfile['yt$firstName']['$t'] };
      } else {
        profile.name = { familyName: '', givenName: youtubeProfile['title']['$t']};
      }

      delete youtubeProfile['xmlns'];
      delete youtubeProfile['xmlns$gd'];
      delete youtubeProfile['xmlns$yt'];
      delete youtubeProfile['xmlns$media'];
      delete youtubeProfile['yt$googlePlusUserId'];
      delete youtubeProfile['yt$location'];
      delete youtubeProfile['yt$statistics'];
      delete youtubeProfile['yt$username'];

      profile._raw = body;
      profile._json = youtubeProfile;

      done(null, profile);
    } catch(e) {
      done(e);
    }
  });
};

Strategy.prototype._convertProfileFields = function(profileFields) {
  var map = {
    'id':          'id',
    'username':    'username',
    'displayName': 'name',
    'name':       ['last_name', 'first_name']
  };

  var fields = [];

  profileFields.forEach(function(f) {
    if (typeof map[f] === 'undefined') return;

    if (Array.isArray(map[f])) {
      Array.prototype.push.apply(fields, map[f]);
    } else {
      fields.push(map[f]);
    }
  });

  return fields.join(',');
};


Strategy.prototype.authorizationParams = function(options) {
  var params = {};
  if (options.accessType) {
    params['access_type'] = options.accessType;
  }
  if (options.approvalPrompt) {
    params['approval_prompt'] = options.approvalPrompt;
  }
  if (options.prompt) {
    // This parameter is undocumented in Google's official documentation.
    // However, it was detailed by Breno de Medeiros (who works at Google) in
    // this Stack Overflow answer:
    //  http://stackoverflow.com/questions/14384354/force-google-account-chooser/14393492#14393492
    params['prompt'] = options.prompt;
  }
  if (options.loginHint) {
    // This parameter is derived from OpenID Connect, and supported by Google's
    // OAuth 2.0 endpoint.
    //   https://github.com/jaredhanson/passport-google-oauth/pull/8
    //   https://bitbucket.org/openid/connect/commits/970a95b83add
    params['login_hint'] = options.loginHint;
  }
  if (options.userID) {
    // Undocumented, but supported by Google's OAuth 2.0 endpoint.  Appears to
    // be equivalent to `login_hint`.
    params['user_id'] = options.userID;
  }
  if (options.hostedDomain || options.hd) {
    // This parameter is derived from Google's OAuth 1.0 endpoint, and (although
    // undocumented) is supported by Google's OAuth 2.0 endpoint was well.
    //   https://developers.google.com/accounts/docs/OAuth_ref
    params['hd'] = options.hostedDomain || options.hd;
  }
  return params;
};


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
