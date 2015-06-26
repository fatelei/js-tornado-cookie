/**
 * Implement the python tornado cookie
 */

var crypto = require('crypto');

var signed_value_version_re = /^([1-9][0-9]*)\|(.*)$/;
var DEFAULT_SIGNED_VALUE_MIN_VERSION = 1;


/**
 * Create the signature
 * @param  {Array} ary The array contains the unhashed values
 * @return {String} The cryptoed value
 */
var createSignatureV1 = function (ary, secret) {
  var hash = crypto.createHmac("sha1", secret);
  var length = ary.length;
  var i = 0;
  var tmp = null;

  for (i = 0; i < length; i++) {
    tmp = ary[i];
    if (typeof ary[i] !== 'string') {
      tmp = tmp.toString();
    }
    hash.update(tmp);
  }
  return hash.digest("hex");
};

var createSignatureV2 = function (s, secret) {
  var hash = crypto.createHmac("sha256", secret);
  hash.update(s);
  return hash.digest('hex');
};

/**
 * Check time whether it is independent equals
 * @param  {String} a
 * @param  {String} b
 * @return {Boolean}
 */
var timeIndependentEquals = function (a, b) {
  if (a.length !== b.length) {
    return false;
  }

  var len = a.length;
  var result = 0;
  var i = 0;

  var tmpA = null;
  var tmpB = null;

  for (i = 0; i < len; i++) {
    tmpA = a[i].charCodeAt(0);
    tmpB = b[i].charCodeAt(0);

    result |= tmpA ^ tmpB;
  }
  return result === 0;
};

var consumeFieldV2 = function (s) {
  var fs = s.indexOf(':');
  var length = s.slice(0, fs);
  var rest = s.slice(fs + 1);

  var n = parseInt(length, 10);
  var field = rest.slice(0, n);

  if (rest.slice(n, n + 1) !== '|') {
    console.error('malformed v2 signed value field');
    return null;
  }

  rest = rest.slice(n + 1);
  return [field, rest];
};

/**
 * Decode signed value version 1
 * @param  {String} name       Cookie name
 * @param  {String} value      Cookie value
 * @return {String}
 */
var decodeSignedValueV1 = function (name, value, secret, days) {
  var parts = value.split("|");

  // for safe check
  if (parts.length !== 3) {
    return null;
  }

  var ary = [name, parts[0], parts[1]];
  var sig = createSignatureV1(ary, secret);
  var timeEqualed = timeIndependentEquals(parts[2], sig);

  if (timeEqualed === 0) {
    return null;
  }

  var timestamp = parseInt(parts[1], 10);
  var now = Math.floor((new Date()).getTime() / 1000);
  var maxAgeDays = days * 86400;

  if (timestamp < (now - maxAgeDays)) {
    console.error('Expired cookie ' + value);
    return null;
  }

  if (timestamp > now + 31 * 86400) {
    console.error('Cookie timestamp in future; possible tampering ' + value);
    return null;
  }

  if (parts[1].indexOf('0') === 0) {
    console.error('Tampered cookie ' + value);
    return null;
  }

  try {
    var base64Str = new Buffer(parts[0], 'base64').toString('utf8');
    return base64Str;
  } catch (err) {
    console.error(err);
    return null;
  }
};

/**
 * Decode signed value version 2
 * @param  {String} name       Cookie name
 * @param  {String} value      Cookie value
 * @return {String}
 */
var decodeSignedValueV2 = function (name, value, secret, days) {
  var rest = value.slice(2);

  var rst = consumeFieldV2(rest);

  if (rst === null) {
    return null;
  }

  // Get key version
  var keyVersion = rst[0];
  rest = rst[1];

  // Get timestamp
  rst = consumeFieldV2(rest);

  if (rst === null) {
    return null;
  }

  var timestamp = rst[0];
  rest = rst[1];

  // Get name field
  rst = consumeFieldV2(rest);

  if (rst === null) {
    return null;
  }

  var nameField = rst[0];
  rest = rst[1];

  // Get value field
  rst = consumeFieldV2(rest);

  if (rst === null) {
    return null;
  }

  var valueField = rst[0];
  rest = rst[1];

  var passedSig = rest;
  var signedString = value.slice(0, -passedSig.length);
  var expectedSig = createSignatureV2(signedString, secret);

  if (!timeIndependentEquals(passedSig, expectedSig)) {
    return null;
  }

  if (nameField !== name) {
    return null;
  }

  timestamp = parseInt(timestamp, 10);
  var now = Math.floor((new Date()).getTime() / 1000);
  var maxAgeDays = days * 86400;

  if (timestamp < now - maxAgeDays) {
    return null;
  }

  try {
    var base64Str = new Buffer(valueField, 'base64').toString('utf8');
    return base64Str;
  } catch (err) {
    console.error(err);
    return null;
  }
};

function TornadoCookie(cookie, secret, options) {
  // Get cookie object.
  this.cookieObj = null;

  if (typeof cookie !== 'object') {
    this.cookieObj = this.parseCookie(cookie);
  } else {
    this.cookieObj = cookie;
  }

  this.days = 31; // Default expired days.

  // Get config.
  if (options !== undefined) {
    if (typeof options === 'object') {
      if (options.hasOwnProperty('days')) {
        this.days = options.days;
      }
    }
  }

  this.secret = secret; // Cookie secret.
}

/**
 * Parse the cookie to object.
 * @param  {String} cookie The cookie's value
 * @return {Object} The parsed cookie object
 */
TornadoCookie.prototype.parseCookie = function (cookie) {
  var ary = cookie.split('; ');
  var obj = {};
  var i = 0;
  var length = ary.length;

  var index = null;
  var key = null;
  var value = null;

  for (i = 0; i < length; i++) {
    index = ary[i].indexOf("=");

    key = ary[i].slice(0, index);
    value = ary[i].slice(index + 1);
    obj[key]  = value;
  }
  return obj;
};

/**
 * Decode signed value
 * @param  {String} name
 * @return {String} decoded cookie value
 */
TornadoCookie.prototype.getSecureCookie = function (name) {
  var value = this.cookieObj[name];

  if (value === null) {
    return null;
  }

  // Get cookie version.
  var minVersion = DEFAULT_SIGNED_VALUE_MIN_VERSION;

  var m = value.match(signed_value_version_re);
  var version = null;

  if (m === null) {
    version = 1;
  } else {
    version = parseInt(m[1], 10);

    if (isNaN(version)) {
      version = 1;
    } else {
      if (version > 999) {
        version = 1;
      }
    }
  }

  if (version < minVersion) {
    return null;
  }

  if (version === 1) {
    return decodeSignedValueV1(name, value, this.secret, this.days);
  }

  if (version === 2) {
    return decodeSignedValueV2(name, value, this.secret, this.days);
  }

  return null;
};

module.exports = TornadoCookie;
