# Quickie Install

```
npm -g install Haraka
haraka -i haraka-server-config

git clone https://github.com/snoj/haraka-secwrap.git
cp -R ./haraka-secwrap/* ./haraka-server-config

cd haraka-server-config

npm install

#edit config/rcpt_to.secwrap with your favorite text editor
nano config/rcpt_to.secwrap

#enable secwrap
echo secwrap/secwrap >> config/smtp.ini

#run
haraka -c .
```

See install.md for more/expanded details.

# Other interesting stuff

[Mailvelope](https://www.mailvelope.com/) Chrome/Firefox addon to encrypt/decrypt text in the browser.
