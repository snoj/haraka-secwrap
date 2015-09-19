# Setup secwrap

## Download secwrap

```
git clone https://github.com/snoj/haraka-secwrap.git
```

## Install haraka and initiate the config.
```
sudo npm -g install Haraka
mkdir ./secwrap-instance
haraka -i ./secwrap-instance
cp -R ./haraka-secwrap/* ./secwrap-instance 
```

## Install some npm modules
```
cd ./secwrap-instance
npm install lodash memory-stream openpgp
```

## Edit the rcpt_to.secwrap file

```
{
  "example.com" : {
    "address or *": {
      "addr": "address to forward msg to"
      ,"key": "PGP public key to use"
    }
  }
}
```

## Enable secwrap

```
echo secwrap/secwrap >> ./config/plugins
```

## Start haraka

```
sudo haraka -c . 
```
