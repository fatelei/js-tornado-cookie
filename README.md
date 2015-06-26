# js-tornado-cookie
Used for parse python tornado generated cookie.

## Install

```
npm install js-tornado-cookie
```

## API

+ new TornadoCookie(cookie, secret, {days: 31});
	+ cookie: Cookie string
	+ secret: Tornado cookie secret
	+ options: 		
		+ days: Cookie expired days, default is 31. 


## Usage

```
var TornadoCookie = require('js-tornado-cookie');

var tc = new TornadoCookie('cookie', 'cookie secret', {days: 31});
console.log(tc.getSecureCookie('name'));
```