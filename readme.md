# Quickie Install

```
npm -g install Haraka
haraka -i haraka-server-config
cd ./haraka-server-config
npm install snoj/haraka-secwrap

#enable secwrap
echo haraka-secwrap >> config/plugins

#create and edit config/secwrap. Urls can be whatever you want them to be. (Uses lodash _.template().)
{
  "userlookup": "http://localhost:8025/from/${ mail_from }/to/${ rcpt_to }"
  ,"storage": "http://localhost:8025/mailbox/${ mailbox }"
  ,"local": { //for self contained setups
    "a.example.com": {
      "key": "====KEY==== blahblahblahblahblahblah =====END KEY===="
      ,"forward": "joeblack@b.example.com"
      ,"hidesender": true
    }
    ,"Megan@c.example.com": {
      "key": "====KEY==== blahblahblahblahblahblah =====END KEY===="
      ,"forward": "MeganMcExample@b.example.com"
      ,"hidesender": true
    }
  }
}

#create http(s) server using express or restify to handle urls from config/secwrap

#run
haraka -c .
```

# REST Server
## User Lookup, must return status code 200

```
{
  "key": "user's public PGP/GPG key",
  "mailbox": "optional. if set, secwrap will use the storage url. can be any sort of identifying string.",
  "forward": "optional. if set, encrypted mail will be sent to this address."
  "hidesender": "optional. truthy. hides the address the original email was sent from."
}
```

## Storage

JSON sent to the REST server

```
{
  "mailbox": "id given by the user lookup data"
  "mail_from": "either the actual sender or gibberish depending on hidesender"
  "rcpt_to": "the email address of the recipient"
  "message": "encrypted message"
  "keythumbprint": "Thumbprint of the key used to encrypt the message"
}
```

# Other interesting stuff

[Mailvelope](https://www.mailvelope.com/) Chrome/Firefox addon to encrypt/decrypt text in the browser.
