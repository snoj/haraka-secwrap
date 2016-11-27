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
  MemoryStream = require('memory-stream'),
  async = require('async');

//might not be the brightest of ideas...but I'm out of others 
//since root doesn't seem to inherit NODE_PATH and plugins loaded
//from haraka_dir/node_modules can't find native haraka tools 
//like ./outbound.js
var outbound = require(_.keys(require.cache).find(function(v) {
  return /haraka\/outbound\.js$/i.test(v);
}) || './outbound.js');
var Address = require(_.keys(require.cache).find(function(v) {
  return /address-rfc2821/i.test(v);
}) || './address.js').Address;

exports.register = function() {
  plugin = this;
  rests_loader = function() {
    rests = plugin.config.get('secwrap', 'json', rests_loader);
    rest_userlookup = _.template(rests.userlookup || "");
    rest_storage = _.template(rests.storage || "");
  };
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
    host: rcpt.host,
    rcpt_to: rcpt.address(),
    mail_from: ""
  });

  //todo promise this up
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
    plugin.logdebug("running user lookup ", tUrl);
    request({url: tUrl}, function(err, res, body) {
      if(!!err || res.statusCode != 200) {
        plugin.logerror("user lookup failed", body);
        next(CONT);
        return;
      }

      plugin.logdebug("user lookup succeeded ", JSON.parse(body));

      connection._secwrap = JSON.parse(body);
      connection.transaction.parse_body = true;
      next(OK);
    });
  }
};

exports.secwrap_queue = function(next, connection, params) {

  plugin.logdebug("preparing secwrap queue: ", !!connection._secwrap, !!connection.transaction.body);
  if (!!!connection._secwrap) 
    return next(CONT); //no user? Skip it!


  var transaction = connection.transaction;
  var mail_from = transaction.mail_from;
  var rcpt_to = transaction.rcpt_to;
  var _secwrap = connection._secwrap;

  plugin.logdebug("message for ", rcpt_to.toString(), "forward=", !!_secwrap.forward, " mailbox=", !!_secwrap.mailbox);

  if (!!transaction.body) {
    try {
      var ms = new MemoryStream();
      transaction.message_stream.pipe(ms);
      
      ms.on('finish', function() {
        var publicKey = openpgp.key.readArmored(_secwrap.key);
        var eopts = {
          publicKeys: publicKey.keys,
          data: ms.toString('ascii')
        };
        openpgp.encrypt(eopts).then(function(encMsg) {
          //Hide the sender if we're told to.
          var tMail_from = (!!!_secwrap.hidesender) ? mail_from.toString() : "secmail@" + hostname;

          async.auto({
            forward: function(cb, obj) {
              if(!!!_secwrap.forward) {
                cb();
                return;
              }
              var mci_opts = {
                from: tMail_from,
                to: rcpt_to.toString(),
                subject: "Encrypted Message",
                attachments: [{
                  filename: "email.eml.gpg",
                  contents: encMsg,
                  contentType: "application/pgp-encrypted"
                }],
                text: "A message from the NSA."
              };
              var mci = MailComposer(mci_opts);
              mci.build(function(err, compiledMsg) {
                if (!!err) {
                  //return next(DENY, "Encryption error");
                  cb("Wrapping for forward error");
                  return;
                }
                outbound.send_email(tMail_from, _secwrap.forward, compiledMsg.toString('ascii'));
                cb(null);
              });
            },
            mailbox: function(cb) {
              if(!!!_secwrap.mailbox) {
                cb(null);
                return;
              }

              var doc = {
                arrived: Date.now(),
                mail_from: tMail_from,
                rcpt_to: rcpt_to.toString(),
                message: encMsg,
                mailbox: _secwrap.mailbox,
                keythumbprint: publicKey.keys[0].primaryKey.getFingerprint()
              };

              var url = rest_storage({
                mailbox: _secwrap.mailbox,
                rcpt_to: _secwrap.addr,
                mail_from: mail_from
              });

              plugin.logdebug("posting message to ", url);

              request({url: url, method: "POST", json: doc}, function(err, resp) {
                if(err) {
                  plugin.logerror(err, resp);
                  cb(err);
                  return;
                }

                plugin.logdebug("POSTED message");
                cb(null);
              });
            }
          }, function(err, results) {
            if(!!err)
              next(DENY);
            else
              next(OK);
          });
        }).catch(function(ex) {
          plugin.logdebug("promise exception: ", arguments, ex.stack);
          next(DENY, "promise exception");
        });
      });
    } catch (ex) {
      plugin.logdebug("exception: ", ex);
      next(DENY, "exception");
    }
  } else {
    next(DENY, "no body"); 
  }
};
