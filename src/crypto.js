const libsodium = require('libsodium-wrappers');

class Crypto {
  constructor() {
    return (async () => {
      await libsodium.ready;
      this._sodium = libsodium;

      return this;
    })();
  }

  /*
  * Receives buffer attributes. Returns buffer ciphertext.
  */
  encrypt(data, pk, nonce) {
    // Encrypt
    const cipherData = this._sodium.crypto_secretbox_easy(data, nonce, pk);
    // Remove plaintext value from memory
    // delete pk.plaintextKey;

    return cipherData;
  }

  decrypt(cipherData, pk, nonce) {
    // Decrypt
    const plaintextData = this._sodium.crypto_secretbox_open_easy(cipherData, nonce, pk);

    // Remove plaintext value from memory

    return plaintextData;
  }

  /*
  * Receives buffer attributes. Returns JSON with content encoded in Bas64.
  */
  fileCipherObject(cipherData, ck, nonce) {
    return {
      'data': Buffer.from(cipherData).toString('base64'),
      'key': Buffer.from(ck).toString('base64'),
      'nonce': Buffer.from(nonce).toString('base64')
    };
  }
}

export default Crypto;
