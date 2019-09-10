const libsodium = require('libsodium-wrappers');

/** Class that holds all cryptographic functionality. */
export class Crypto {
  /** Create an instance of Crypto. */
  constructor() {
    return (async () => {
      await libsodium.ready;
      this._sodium = libsodium;

      return this;
    })();
  }

  /**
    * @param {Uint8Array|String} data - Plaintext to be encrypted.
    * @param {Uint8Array} pk - Public key used for symmetric encryption.
    * @param {Uint8Array} nonce - To be used one time only.
    * @return {Uint8Array} Ciphertext value.
    */
  encrypt(data, pk, nonce) {
    const cipherData = this._sodium.crypto_secretbox_easy(data, nonce, pk);

    // Remove plaintext value from memory
    pk = null;

    return cipherData;
  }

  /**
    * @param {Uint8Array} cipherData - Ciphertext to be decrypted.
    * @param {Uint8Array} pk - Public key used for symmetric encryption.
    * @param {Uint8Array} nonce - To be used one time only.
    * @return {Uint8Array} Plaintext value.
    */
  decrypt(cipherData, pk, nonce) {
    const plaintextData = this._sodium.crypto_secretbox_open_easy(cipherData,
        nonce,
        pk);

    // Remove plaintext value from memory
    pk = null;

    return plaintextData;
  }

  /**
    * @param {Uint8Array} cipherData - Ciphertext to be decrypted.
    * @param {Uint8Array} ck - Private key used for symmetric encryption.
    * @param {Uint8Array} nonce - To be used one time only.
    * @return {JSON} Cipher object with Bas64 encoded values.
    */
  fileCipherObject(cipherData, ck, nonce) {
    return {
      'data': Buffer.from(cipherData).toString('base64'),
      'key': Buffer.from(ck).toString('base64'),
      'nonce': Buffer.from(nonce).toString('base64'),
    };
  }
}
