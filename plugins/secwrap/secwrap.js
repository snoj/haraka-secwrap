var _ = require('lodash'),
  util = require('util'),
  plugin = null,
  Address = require('./address').Address,
  aliases = {},
  openpgp = require('openpgp'),
  request = require('request'),
  outbound = require('./outbound'),
  MailComposer = require('mailcomposer').MailComposer,
  MemoryStream = require('memory-stream');

exports.register = function() {
  //setup db
  request({url: 'http://localhost:5984/emails', method: 'PUT'});

  plugin = this;
  aliases = plugin.config.get('secwrap', 'json', function() {
    aliases = plugin.config.get('secwrap', 'json');
  });

  this.register_hook('rcpt', 'secwrap_allowed');
  this.register_hook('queue', 'secwrap_queue');
};


exports.secwrap_allowed = function(next, connection, params) {
  var 
      rcpt = params[0],
      _secwrap;
  
  if (aliases[rcpt.host] && aliases[rcpt.host].addrs && (aliases[rcpt.host].addrs[rcpt.user] || aliases[rcpt.host].addrs["*"])) {
    _secwrap = aliases[rcpt.host].addrs[rcpt.user] || aliases[rcpt.host].addrs["*"];
    if (!!_secwrap) {
      connection._secwrap = _secwrap
      connection.transaction.parse_body = true;
      return next(OK);
    }
  }
  next(CONT);
};

exports.secwrap_queue = function(next, connection, params) {

  if (!!!connection._secwrap) 
    return next(CONT);

  var transaction = connection.transaction;
  var mail_from = transaction.mail_from;
  var rcpt_to = transaction.rcpt_to;
  var _secwrap = connection._secwrap;

  if (!!transaction.body) {
    try {
      var ms = new MemoryStream();
      transaction.message_stream.pipe(ms);
      
      ms.on('finish', function() {
        var publicKey = openpgp.key.readArmored(_secwrap.key);

        openpgp.encryptMessage(publicKey.keys, ms.toString('ascii')).then(function(encMsg) {
          var mci = new MailComposer();

          mci.setMessageOption({
            from: mail_from
            ,to: rcpt_to
            ,subject: "Encrypted Message"
          });

          mci.addAttachment({
            filename: "email.eml.gpg"
            ,contents: encMsg
            ,contentType: "application/pgp-encrypted"
          });

          mci.buildMessage(function(err, compiledMsg) {
            if (!!err)
              return next(DENY, "Encryption error");

            outbound.send_email(mail_from, _secwrap.addr, compiledMsg);
            next(OK);
          });

          var doc = {
            arrived: Date.now()
            ,rcpt_to: rcpt_to
            ,data: encMsg
            ,unread: true
            ,downloaded: false
          };

          request({url: 'http://localhost:5984/emails', method: "post", json: doc});
        }).catch(function() {
          next(DENY, "promise exception");
        });
      })
    } catch (ex) {
      next(DENY, "exception");
    }
  } else {
    next(DENY, "no body"); 
  }
}
