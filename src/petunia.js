let Crypto = require('./crypto.js');

module.exports =  class Petunia {
  constructor() {
    return (async () => {
      this.crypto = await new Crypto();
      return this;
    })();
  }

  encrypt(data, keys, nonce) {
    return this.crypto.encrypt(data, keys, nonce);
  }

  decrypt(data, keys, nonce) {
    return this.crypto.decrypt(data, keys, nonce);
  }

  fileCipherObject(cipherData, ck, nonce) {
    return this.crypto.fileCipherObject(cipherData, ck, nonce);
  }
}

// let hola = ' Hola';

// module.exports = Petunia, hola;
