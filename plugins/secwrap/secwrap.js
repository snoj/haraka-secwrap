var
  Address = require('./address').Address,
  util = require('util'),
  outbound = require('./outbound'),
  openpgp = require('openpgp');
var _ = require('lodash');
var MemoryStream = require('memory-stream');

exports.register = function () {
  //this.logdebug("openpgp", openpgp.encryptMessage);
  //this.logdebug("outbound", outbound.send_email);

  this.logdebug("config", this.config.get('rcpt_to.secwrap', 'json'));
  
  this.register_hook('rcpt', 'secwrap_allowed');
  this.register_hook('queue', 'secwrap_queue');
};

exports.secwrap_allowed = function(next, connection, params) {
  var
    plugin = this,
    aliases = this.config.get('rcpt_to.secwrap', 'json') || {},
    rcpt = params[0],
    _secwrap;
  if(aliases[rcpt.host] && aliases[rcpt.host].addrs && (aliases[rcpt.host].addrs[rcpt.user] || aliases[rcpt.host].addrs["*"])) {
    _secwrap = aliases[rcpt.host].addrs[rcpt.user] || aliases[rcpt.host].addrs["*"];
    /*if(!util.isArray(_secwrap))
      _secwrap = [ _secwrap ];*/

    if(!!_secwrap) {
      connection._secwrap = _secwrap
      connection.transaction.parse_body = true;
      return next(OK);
    }
    /*connection.transaction.rcpt_to.pop();
    connection.relaying = true;
    _secwrap.forEach(function(address) {
      plugin.loginfo('Relaying to: ' + address);
      connection.transaction.rcpt_to.push(new Address('<' + address + '>'));
    });
    return next(OK);*/
  }
  next(CONT);
};

exports.secwrap_queue = function(next, connection, params) {

  if(!!!connection._secwrap) 
    return next(CONT);

  var transaction = connection.transaction;
  var mail_from = transaction.mail_from;
  var rcpt_to = transaction.rcpt_to;
  var _secwrap = connection._secwrap;
  var msg = "";
  var data;

  if(!!transaction.body) {
    try{
      var plugin = this;
      var ms = new MemoryStream();
      transaction.message_stream.pipe(ms);
      
      ms.on('finish', function() {
        var publicKey = openpgp.key.readArmored(_secwrap.key);
        openpgp.encryptMessage(publicKey.keys, ms.toString('ascii')).then(function(encMsg) {
          
          var contents = [
            "From: " + mail_from,
            "To: " + _secwrap.addr,
            "MIME-Version: 1.0",
            "Content-type: text/plain; charset=us-ascii",
            "Subject: Some subject here",
            "Message-Id: <" + Date.now() + Math.random() + "@enc.snoj.us>",
            "",
            encMsg
          ];
          outbound.send_email(mail_from, _secwrap.addr, contents.join("\n"));
          next(OK);
        }).catch(function() {
          next(DENY, "promise exception");
        });
      })
    }catch (ex) {
      next(DENY, "exception");
    }
  } else {
    next(DENY, "no body"); 
  }
}
