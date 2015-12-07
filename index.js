var _ = require('lodash'),
  util = require('util'),
  plugin = null,
  hostname = "localhost",
  rests = {},
  rest_userlookup = function() {},
  rest_storage = function() {},
  rests_loader = null,
  openpgp = require('openpgp'),
  request = require('request'),
  MailComposer = require('mailcomposer'),
  MemoryStream = require('memory-stream');

//might not be the brightest of ideas...but I'm out of others 
//since root doesn't seem to inherit NODE_PATH and plugins loaded
//from haraka_dir/node_modules can't find native haraka tools 
//like ./outbound.js
var outbound = require(_.keys(require.cache).find(function(v) { return /haraka\/outbound\.js$/i.test(v); }) || './outbound.js');
var Address = require(_.keys(require.cache).find(function(v) { return /haraka\/address\.js$/i.test(v); }) || './address.js').Address;
exports.register = function() {
  plugin = this;
  rests_loader = function() {
    rests = plugin.config.get('secwrap', 'json', rests_loader);
    rest_userlookup = _.template(rests.userlookup || "");
    rest_storage = _.template(rests.storage || "");
  }
  hostname = plugin.config.get("me");

  rests_loader();

  this.register_hook('rcpt', 'secwrap_allowed');
  this.register_hook('queue', 'secwrap_queue');
};


exports.secwrap_allowed = function(next, connection, params) {
  var 
      rcpt = params[0],
      _secwrap;

  var tUrl = rest_userlookup({
    host: rcpt.host
    ,rcpt_to: rcpt.user
    ,mail_from: ""
  });

  if(rests.local) {
    var addr = new Address(rcpt);
    if(typeof rests.local[addr.address()] !== 'undefined')
      connection._secwrap = rests.local[addr.address()];
    else if(typeof rests.local[addr.host] !== 'undefined')
      connection._secwrap = rests.local[addr.host];

    if(!!connection._secwrap) {
      connection.transaction.parse_body = true;
      next(OK);
    }
  }

  if(!!!connection._secwrap) {
    request({url: tUrl}, function(err, res, body) {
      if(!!err || res.statusCode != 200) {
        next(CONT);
        return;
      }

      connection._secwrap = body;
      connection.transaction.parse_body = true;
      next(OK);
    });
  }
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
          var tMail_from = (!!!_secwrap.hidesender) ? mail_from : "secmail@" + hostname;
          var mci_opts = {
            from: tMail_from
            ,to: rcpt_to.toString()
            ,subject: "Encrypted Message"
            ,attachments: [{
              filename: "email.eml.gpg"
              ,contents: encMsg
              ,contentType: "application/pgp-encrypted"
            }]
            ,text: "A message from the NSA."
          };
          var mci = MailComposer(mci_opts);

          mci.build(function(err, compiledMsg) {
            if (!!err)
              return next(DENY, "Encryption error");

            if(!!_secwrap.forward) {
              outbound.send_email(tMail_from, _secwrap.forward, compiledMsg.toString('ascii'));
            }
            if(!!_secwrap.mailbox) {
              var doc = {
                arrived: Date.now()
                ,mail_from: tMail_from
                ,rcpt_to: rcpt_to
                ,message: encMsg
                ,keythumbprint: ""
              };

              var url = rest_storage({
                mailbox: _secwrap.mailbox
                ,rcpt_to: _secwrap.addr
                ,mail_from: mail_from
              });
              request({url: url, method: 'PUT'}, function() {
                request({url: url, method: "POST", json: doc});
              });
            }
            next(OK);
          });
        }).catch(function(ex) {
          plugin.logdebug("promise exception: ", arguments, ex.stack);
          next(DENY, "promise exception");
        });
      })
    } catch (ex) {
      plugin.logdebug("exception: ", ex);
      next(DENY, "exception");
    }
  } else {
    next(DENY, "no body"); 
  }
}
