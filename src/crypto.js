const libsodium = require('libsodium-wrappers');

export class Crypto {
  constructor() {
    return (async () => {
      await libsodium.ready;
      this._sodium = libsodium;

      return this;
    })();
  }

  /*
  *  Receives buffer attributes. Returns buffer ciphertext.
  */
  encrypt(data, pk, nonce) {
    const cipherData = this._sodium.crypto_secretbox_easy(data, nonce, pk);

    // Remove plaintext value from memory
    pk = null;

    return cipherData;
  }

  /*
  *  Receives buffer attributes. Returns buffer ciphertext.
  */
  decrypt(cipherData, pk, nonce) {
    const plaintextData = this._sodium.crypto_secretbox_open_easy(cipherData, nonce, pk);

    // Remove plaintext value from memory
    pk = null;

    return plaintextData;
  }

  /*
  *  Receives buffer attributes. Returns JSON with Bas64 encoded content.
  */
  fileCipherObject(cipherData, ck, nonce) {
    return {
      'data': Buffer.from(cipherData).toString('base64'),
      'key': Buffer.from(ck).toString('base64'),
      'nonce': Buffer.from(nonce).toString('base64')
    };
  }
}
