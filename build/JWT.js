(function() {
  var JWT, JWTSimple, TOKEN, Type, Url;

  Url = require('url');

  Type = require('type-of-is');

  JWTSimple = require('jwt-simple');

  TOKEN = {
    Expires: 'exp',
    Issuer: 'iss'
  };

  JWT = (function() {
    function JWT(args) {
      if (args == null) {
        args = {};
      }
      this.secret = args.secret;
      this.User = args.User;
    }

    JWT.prototype.encode = function(user) {
      var body, expires, token;
      body = {};
      body[TOKEN.Issuer] = user.id();
      expires = Type(user.tokenExpires, Function) ? user.tokenExpires() : null;
      if (expires) {
        body[TOKEN.Expires] = expires;
      }
      token = JWTSimple.encode(body, this.secret);
      return {
        token: token,
        expires: expires,
        user: user
      };
    };

    JWT.prototype.decode = function(token) {
      var body, expired, expires, now;
      body = JWTSimple.decode(token, this.secret);
      expires = body[TOKEN.Expires];
      expired = expires ? (now = Date.now(), expires < now) : false;
      if (expired) {
        return null;
      } else {
        return body[TOKEN.Issuer];
      }
    };

    JWT.prototype.handle = function(request, response, next) {
      var query, token;
      query = Url.parse(request.url, true).query;
      token = query.token;
      if (!token) {
        return next();
      }
      request.token = token;
      return this._decodeTokenAndFindUser({
        token: token,
        target: request,
        callback: next
      });
    };

    JWT.prototype.handleMessage = function(args) {
      var callback, message, token;
      message = args.message, callback = args.callback;
      token = message.token;
      if (!token) {
        return callback();
      }
      return this._decodeTokenAndFindUser({
        token: token,
        target: message,
        callback: callback
      });
    };

    JWT.prototype._decodeTokenAndFindUser = function(args) {
      var callback, error, has_finder, target, token, user_id;
      token = args.token, target = args.target, callback = args.callback;
      user_id = this.decode(token);
      if (!user_id) {
        return callback();
      }
      target.user_id = user_id;
      target.user = null;
      has_finder = this.User && Type(this.User.findByToken, Function);
      if (!has_finder) {
        error = new Error("User does not define findByToken");
        return callback(error);
      }
      return this.User.findByToken({
        token: token,
        id: user_id,
        callback: function(error, user) {
          if ((!error) && user) {
            target.user = user;
          }
          return callback(error);
        }
      });
    };

    return JWT;

  })();

  module.exports = JWT;

}).call(this);
