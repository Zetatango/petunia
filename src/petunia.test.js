import 'babel-polyfill';
import {Petunia} from './petunia.js';
import {Crypto} from './crypto.js';
jest.mock('./crypto.js');

describe('petunia class', () => {
  it('loads crypto class', async () => {
    const petunia = await new Petunia();

    expect(Crypto).toHaveBeenCalledTimes(1);
    expect(petunia.crypto).toBeDefined();
  });
});

describe('exposes crypto methods', () => {
  beforeAll(() => {
    Crypto.mockClear();
  });

  it('exposes encrypt', async () => {
    const petunia = await new Petunia();
    petunia.encrypt('data', 'key', 'nonce');

    const mockCryptoInstance = Crypto.mock.instances[0];
    const mockEncrypt = mockCryptoInstance.encryptWithKey;

    expect(mockEncrypt).toHaveBeenCalledTimes(1);
  });

  it('exposes decrypt', async () => {
    const petunia = await new Petunia();
    petunia.decrypt('data', 'key', 'nonce');

    const mockCryptoInstance = Crypto.mock.instances[0];
    const mockDecrypt = mockCryptoInstance.decryptWithKey;

    expect(mockDecrypt).toHaveBeenCalledTimes(1);
  });

  it('exposes fileCipherObject', async () => {
    const petunia = await new Petunia();
    petunia.fileCipherObject('data', 'key', 'nonce');

    const mockCryptoInstance = Crypto.mock.instances[0];
    const mockFileCipherObject = mockCryptoInstance.fileCipherObject;

    expect(mockFileCipherObject).toHaveBeenCalledTimes(1);
  });
});
