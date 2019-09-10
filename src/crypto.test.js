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
  const nonceMock = new Uint8Array(nonceBuff);
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
    beforeEach(() => {
      crypto._sodium.randombytes_buf = jest.fn(() => nonceMock);
    });

    it('works with string data', () => {
      const {ciphertext, nonce} = crypto.encryptWithKey(samplePlainText, key);

      expect(sampleCipherView.toString()).toEqual(ciphertext.toString());
      expect(nonce.toString()).toEqual(nonceMock.toString());
    });

    it('works with unit8array data', () => {
      const sampleUint8ArrayTxt = new Uint8Array(samplePlainTextBuffer);
      const {ciphertext, nonce} = crypto.encryptWithKey(sampleUint8ArrayTxt, key);

      expect(sampleCipherView.toString()).toEqual(ciphertext.toString());
      expect(nonce.toString()).toEqual(nonceMock.toString());
    });

    it('raises error if key is invalid', () => {
      expect(() => {
        crypto.encryptWithKey(samplePlainText, 'invalid_key_length');
      }).toThrow('invalid key length');
    });

    it('raises error if nonce is invalid', () => {
      crypto._sodium.randombytes_buf = jest.fn(() => 'invalid_nonce_length');
      expect(() => {
        crypto.encryptWithKey(samplePlainText, key);
      }).toThrow('invalid nonce length');
    });
  });

  describe('decrypt', () => {
    it('works with unit8array data', () => {
      const plaintextBuff = crypto.decryptWithKey(sampleCipherView, key, nonceMock);
      const plaintext = Buffer.from(plaintextBuff).toString('utf8');

      expect(samplePlainText.toString()).toEqual(plaintext.toString());
    });

    it('raises error if key is invalid', () => {
      expect(() => {
        crypto.decryptWithKey(sampleCipherView, 'invalid_key_length', nonceMock);
      }).toThrow('invalid key length');
    });

    it('raises error if nonce is invalid', () => {
      expect(() => {
        crypto.decryptWithKey(sampleCipherView, key, 'invalid_nonce_length');
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

      const fco = crypto.fileCipherObject(sampleCipherView, key, nonceMock);
      expect(expectedFileCipherObj).toEqual(fco);
    });
  });

  describe('integration', () => {
    beforeEach(() => {
      crypto._sodium.randombytes_buf = jest.fn(() => nonceMock);
    });

    it('can encrypt and decrypt', () => {
      const {ciphertext, nonce} = crypto.encryptWithKey(samplePlainText, key);
      const plaintextBuffer = crypto.decryptWithKey(ciphertext, key, nonce);
      const plaintext = Buffer.from(plaintextBuffer).toString('utf8');

      expect(samplePlainText).toEqual(plaintext);
    });
  });
});
