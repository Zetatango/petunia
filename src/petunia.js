import 'babel-polyfill';
import {Crypto} from './crypto.js';

/** Class that exposes library's public methods. */
export class Petunia {
  /** Create an instance of Petunia. */
  constructor() {
    return (async () => {
      this.crypto = await new Crypto();
      return this;
    })();
  }

  /**
    * @param {Uint8Array|String} data - Plaintext to be encrypted.
    * @param {Uint8Array} key - Public key used for symmetric encryption.
    * @param {Uint8Array} nonce - To be used one time only.
    * @return {Uint8Array} Ciphertext value.
    */
  encrypt(data, key, nonce) {
    return this.crypto.encrypt(data, key, nonce);
  }

  /**
    * @param {Uint8Array} data - Ciphertext to be decrypted.
    * @param {Uint8Array} key - Public key used for symmetric encryption.
    * @param {Uint8Array} nonce - To be used one time only.
    * @return {Uint8Array} Plaintext value.
    */
  decrypt(data, key, nonce) {
    return this.crypto.decrypt(data, key, nonce);
  }

  /**
    * @param {Uint8Array} cipherData - Ciphertext to be decrypted.
    * @param {Uint8Array} key - Private key used for symmetric encryption.
    * @param {Uint8Array} nonce - To be used one time only.
    * @return {JSON} Cipher object with Bas64 encoded values.
    */
  fileCipherObject(cipherData, key, nonce) {
    return this.crypto.fileCipherObject(cipherData, key, nonce);
  }
};
