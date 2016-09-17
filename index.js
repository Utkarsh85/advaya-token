var jwt = require('jsonwebtoken');
var moment= require('moment');
var tokenConfig= require(require('path').resolve('./config/token'));

if(!tokenConfig.secret)
	throw {msg:'Token Secret Required'};

var secret= tokenConfig.secret;
var algorithm= tokenConfig.algorithm || 'HS512';
var validity= tokenConfig.validity||14;



token={};
token.create = function (id,obj) {
	var payload = {
    base: id,
    iat: moment().unix(),
    exp: moment().add(validity, 'days').unix()
  };

  if(obj)
  {
	  for(var key in obj)
	  {
	  	if(['base','iat','exp'].indexOf(key) < 0)
		  	payload[key]=obj[key];
	  }	
  }
  return jwt.sign(payload, secret,{ algorithm: algorithm});
}

token.verify = function (token) {
	try
	{
		var decoded = jwt.verify(token,secret,{ algorithm: algorithm});
	}
	
	catch(err)
	{
		return false;
	}

	if(decoded.exp> moment().unix())
		return true;
	else
		return false;
}

token.payload = function (token) {
	return jwt.decode(token,secret,{ algorithm: algorithm});
}

module.exports= token;