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

    describe('invalid input errors', () => {
      describe('invalid type', () => {
        it('raises error if data is invalid', () => {
          expect(() => {
            crypto.encryptWithKey(new Uint16Array(samplePlainText), key);
          }).toThrow('unsupported input type for message');
        });

        it('raises error if key is invalid', () => {
          expect(() => {
            crypto.encryptWithKey(samplePlainText, new Uint16Array(key));
          }).toThrow('unsupported input type for key');
        });

        it('raises error if nonce is invalid', () => {
          crypto._sodium.randombytes_buf = jest.fn(() => new Uint16Array(nonceMock));
          expect(() => {
            crypto.encryptWithKey(samplePlainText, key);
          }).toThrow('unsupported input type for nonce');
        });
      });

      describe('missing attribute', () => {
        it('raises error if key is missing', () => {
          [null, undefined].forEach(function(val,_index) { 
            expect(() => {
              crypto.encryptWithKey(samplePlainText, val);
            }).toThrow('key cannot be null or undefined');
          });
        });

        it('raises error if data is missing', () => {
          [null, undefined].forEach(function(val,_index) { 
            expect(() => {
              crypto.encryptWithKey(val, key);
            }).toThrow('message cannot be null or undefined');
          });
        });
      });

      describe('invalid length', () => {
        it('raises error if key length is invalid', () => {
          expect(() => {
            crypto.encryptWithKey(samplePlainText, 'invalid_key_length');
          }).toThrow('invalid key length');
        });

        it('raises error if nonce length is invalid', () => {
          crypto._sodium.randombytes_buf = jest.fn(() => 'invalid_nonce_length');
          expect(() => {
            crypto.encryptWithKey(samplePlainText, key);
          }).toThrow('invalid nonce length');
        });
      });
    });
  });

  describe('decrypt', () => {
    it('works with unit8array data', () => {
      const plaintextBuff = crypto.decryptWithKey(sampleCipherView, key, nonceMock);
      const plaintext = Buffer.from(plaintextBuff).toString('utf8');

      expect(samplePlainText.toString()).toEqual(plaintext.toString());
    });

    describe('invalid input errors', () => {
      describe('invalid type', () => {
        it('raises error if cipherData is invalid', () => {
          expect(() => {
            crypto.decryptWithKey(new Uint16Array(sampleCipherView), key, nonceMock);
          }).toThrow('unsupported input type for ciphertext');
        });

        it('raises error if key is invalid', () => {
          expect(() => {
            crypto.decryptWithKey(sampleCipherView, new Uint16Array(key), nonceMock);
          }).toThrow('unsupported input type for key');
        });

        it('raises error if nonce is invalid', () => {
          expect(() => {
            crypto.decryptWithKey(sampleCipherView, key, new Uint16Array(nonceMock));
          }).toThrow('unsupported input type for nonce');
        });
      });

      describe('missing attribute', () => {
        it('raises error if cipherData is missing', () => {
          [null, undefined].forEach(function(val,_index) { 
            expect(() => {
              crypto.decryptWithKey(val, key, nonceMock);
            }).toThrow('ciphertext cannot be null or undefined');
          });
        });

        it('raises error if key is missing', () => {
          [null, undefined].forEach(function(val,_index) { 
            expect(() => {
              crypto.decryptWithKey(sampleCipherView, val, nonceMock);
            }).toThrow('key cannot be null or undefined');
          });
        });

        it('raises error if data is missing', () => {
          [null, undefined].forEach(function(val,_index) { 
            expect(() => {
              crypto.decryptWithKey(sampleCipherView, key, val);
            }).toThrow('nonce cannot be null or undefined');
          });
        });
      });

      describe('invalid length', () => {
        it('raises error if key length is invalid', () => {
          expect(() => {
            crypto.decryptWithKey(sampleCipherView, 'invalid_key_length', nonceMock);
          }).toThrow('invalid key length');
        });

        it('raises error if nonce length is invalid', () => {
          expect(() => {
            crypto.decryptWithKey(sampleCipherView, key, 'invalid_nonce_length');
          }).toThrow('invalid nonce length');
        });
      });
    });
  });

  describe('fileCipherObject', () => {
    const expectedFileCipherObj = {
      'data': sampleCipherB64,
      'key': keyB64,
      'nonce': nonceB64,
    };

    it('works with unit8array data', () => {
      const fco = crypto.fileCipherObject(sampleCipherView, key, nonceMock);
      expect(expectedFileCipherObj).toEqual(fco);
    });

    describe('invalid input errors', () => {
      it('raises error if cipherData is invalid', () => {
        expect(() => {
          crypto.fileCipherObject(new Uint16Array(sampleCipherView), key, nonceMock);
        }).toThrow('Parameter is not a Uint8Array');
      });

      it('raises error if key is invalid', () => {
        expect(() => {
          crypto.fileCipherObject(sampleCipherView, new Uint16Array(key), nonceMock);
        }).toThrow('Parameter is not a Uint8Array');
      });

      it('raises error if nonce is invalid', () => {
        expect(() => {
          crypto.fileCipherObject(sampleCipherView, key, new Uint16Array(nonceMock));
        }).toThrow('Parameter is not a Uint8Array');
      });
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

    it('fails when ciphertext has been tampered', () => {
      const {ciphertext, nonce} = crypto.encryptWithKey(samplePlainText, key);
      let ciphertextB64 = Buffer.from(ciphertext).toString('base64')

      const tamperedCiphertextB64 = ciphertextB64 + 'malicious code';
      const tamperedCiphertextBuffer = Buffer.from(tamperedCiphertextB64, 'base64');
      const tamperedCiphertextView = new Uint8Array(tamperedCiphertextBuffer);

      expect(() => {
        crypto.decryptWithKey(tamperedCiphertextView, key, nonce);
      }).toThrow('wrong secret key for the given ciphertext');
    });

    it('fails when key does not match', () => {
      const {ciphertext, nonce} = crypto.encryptWithKey(samplePlainText, key);
      const badKey = new Uint8Array(32);

      expect(() => {
        crypto.decryptWithKey(ciphertext, badKey, nonce);
      }).toThrow('wrong secret key for the given ciphertext');
    });

    it('fails when nonce does not match', () => {
      const {ciphertext, nonce} = crypto.encryptWithKey(samplePlainText, key);
      const badNonce = new Uint8Array(24);

      expect(() => {
        crypto.decryptWithKey(ciphertext, key, badNonce);
      }).toThrow('wrong secret key for the given ciphertext');
    });
  });
});
