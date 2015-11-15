var _ = require('lodash'),
  util = require('util'),
  plugin = null,
  hostname = "",
  Address = require('./address').Address,
  rests = {},
  rest_userlookup = function() {},
  rest_storage = function() {},
  openpgp = require('openpgp'),
  request = require('request'),
  outbound = require('./outbound'),
  MailComposer = require('mailcomposer').MailComposer,
  MemoryStream = require('memory-stream');


exports.register = function() {
  plugin = this;

  rests_loader = function() {
    rests = plugin.config.get('secwrap', 'json', rests_loader);
    rest_userlookup = _.template(rests.userlookup);
    rest_storage = _.template(rests.storage);
  }
  hostname = plugin.config.get("me");

  rests_loader();

  this.register_hook('rcpt', 'secwrap_allowed');
  this.register_hook('queue', 'secwrap_queue');
};


exports.secwrap_allowed = function(next, connection, params) {
  var 
      rcpt = params[0],
      _secwrap

  var tUrl = rest_userlookup({
    host: rcpt.host
    ,rcpt_to: rcpt.user
    ,mail_from: ""
  });


  request({url: tUrl}, function(err, res, body) {
    if(!!err || res.statusCode != 200) {
      next(CONT);
      return;
    }

    connection._secwrap = body;
    connection.transaction.parse_body = true;
    next(OK);
  });
  //next(CONT);
};

exports.secwrap_queue = function(next, connection, params) {

  if (!!!connection._secwrap) 
    return next(CONT); //no user? Skip it!

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
          var tMail_from = (!!!_secwrap.hidesender) ? mail_from : "secmail@" + hostname;
          mci.setMessageOption({
            from: tMail_from
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

            if(!!_secwrap.forward) {
              outbound.send_email(tMail_from, _secwrap.forward, compiledMsg);
            }
            if(!!_secwrap.mailbox) {
              var doc = {
              arrived: Date.now()
              ,mail_from: tMail_from
              ,rcpt_to: rcpt_to
              ,message: encMsg
              ,keythumbprint: 
            };

            var url = rest_storage({
              mailbox: _secwrap.mailbox
              ,rcpt_to: _secwrap.addr
              ,mail_from: mail_from
            });
            request({url: url, method: 'PUT'}, function() {
              request({url: url, method: "POST", json: doc});
            });
            next(OK);
          });
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
