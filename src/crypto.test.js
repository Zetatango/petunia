import 'babel-polyfill';
import {Crypto} from './crypto.js';

describe('crypto class', () => {
  it('loads libsodium lib', async () => {
    const crypto = await new Crypto();

    expect(crypto._sodium).toBeDefined();
  });
});

describe('crypto class methods', () => {
  let crypto;
  const nonceB64 = 'UgJY4MykLeUh+Sm7SorFiC+GE4Ot+DN8';
  const nonceBuff = Buffer.from(nonceB64, 'base64');
  const keyB64 = 'X1IJ2SFW0oJVcGmmXqTt6Bh1NfD+uf40bkmWW/G8VLs=';
  const keyBuff = Buffer.from(keyB64, 'base64');
  const nonce = new Uint8Array(nonceBuff);
  const key = new Uint8Array(keyBuff);
  const samplePlainText = 'hi';
  const samplePlainTextBuffer = Buffer.from(samplePlainText);
  const sampleCipherB64 = 'bhPvT+MsdXKopRp7jw35CfPh';
  const sampleCipherBuffer = Buffer.from(sampleCipherB64, 'base64');
  const sampleCipherView = new Uint8Array(sampleCipherBuffer);

  beforeAll(async () => {
    crypto = await new Crypto();
  });

  describe('encrypt', () => {
    it('works with string data', () => {
      const ciphertext = crypto.encrypt(samplePlainText, key, nonce);

      expect(sampleCipherView.toString()).toEqual(ciphertext.toString());
    });

    it('works with unit8array data', () => {
      const sampleUint8ArrayText = new Uint8Array(samplePlainTextBuffer);
      const ciphertext = crypto.encrypt(sampleUint8ArrayText, key, nonce);

      expect(sampleCipherView.toString()).toEqual(ciphertext.toString());
    });

    it('raises error if key is invalid', () => {
      expect(() => {
        crypto.encrypt(samplePlainText, 'invalid_key_length', nonce);
      }).toThrow('invalid key length');
    });

    it('raises error if nonce is invalid', () => {
      expect(() => {
        crypto.encrypt(samplePlainText, key, 'invalid_nonce_length');
      }).toThrow('invalid nonce length');
    });
  });

  describe('decrypt', () => {
    it('works with unit8array data', () => {
      const plaintextBuff = crypto.decrypt(sampleCipherView, key, nonce);
      const plaintext = Buffer.from(plaintextBuff).toString('utf8');

      expect(samplePlainText.toString()).toEqual(plaintext.toString());
    });

    it('raises error if key is invalid', () => {
      expect(() => {
        crypto.decrypt(sampleCipherView, 'invalid_key_length', nonce);
      }).toThrow('invalid key length');
    });

    it('raises error if nonce is invalid', () => {
      expect(() => {
        crypto.decrypt(sampleCipherView, key, 'invalid_nonce_length');
      }).toThrow('invalid nonce length');
    });
  });

  describe('fileCipherObject', () => {
    it('works with unit8array data', () => {
      const expectedFileCipherObj = {
        'data': sampleCipherB64,
        'key': keyB64,
        'nonce': nonceB64,
      };

      const fco = crypto.fileCipherObject(sampleCipherView, key, nonce);
      expect(expectedFileCipherObj).toEqual(fco);
    });
  });

  describe('integration', () => {
    it('can encrypt and decrypt', () => {
      const cipherBuffer = crypto.encrypt(samplePlainText, key, nonce);
      const plaintextBuffer = crypto.decrypt(cipherBuffer, key, nonce);
      const plaintext = Buffer.from(plaintextBuffer).toString('utf8');

      expect(samplePlainText).toEqual(plaintext);
    });
  });
});
