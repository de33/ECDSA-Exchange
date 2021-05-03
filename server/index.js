const express = require('express');
const app = express();
const cors = require('cors');
const port = 3042;
const EC = require('elliptic').ec;
const SHA256 = require('crypto-js/sha256');


app.use(cors());
app.use(express.json());

const ec = new EC('secp256k1');

const key1 = ec.genKeyPair();
const key2 = ec.genKeyPair();
const key3 = ec.genKeyPair();

const publicKey1 = key1.getPublic().encode("hex");
const publicKey2 = key2.getPublic().encode("hex");
const publicKey3 = key3.getPublic().encode("hex");

const privateKey1 = key1.getPrivate().toString(16);
const privateKey2 = key2.getPrivate().toString(16);
const privateKey3 = key3.getPrivate().toString(16);

const balances = {
  [publicKey1]: 100,
  [publicKey2]: 50,
  [publicKey3]: 75,
}

app.get('/balance/:address', (req, res) => {
  const {address} = req.params;
  const balance = balances[address] || 0;
  res.send({ balance });
});

app.post('/send', (req, res) => {
  const {sender, recipient, amount, signed} = req.body;
  const publicKey = ec.keyFromPublic(sender, "hex");
  const msg = signed.message;
  const msgHash = SHA256(msg).toString();
  const signature = {
    r: signed.signature.r,
    s: signed.signature.s
  };

  if(publicKey.verify(msgHash, signature)){
    balances[sender] -= amount;
    balances[recipient] = (balances[recipient] || 0) + +amount;
    res.send({ balance: balances[sender] });
  }

});

app.listen(port, () => {
  console.log(`Listening on port ${port}!`);
  console.log(`Wallets (public key, private key, amount), 
    
    Wallet 1: ${publicKey1} ${privateKey1} ${balances[publicKey1]}
    Wallet 2: ${publicKey2} ${privateKey2} ${balances[publicKey2]}
    Wallet 3: ${publicKey3} ${privateKey3} ${balances[publicKey3]}
    
    `);
});
