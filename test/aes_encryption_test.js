const assert = require('assert');
const { aesEncryption } = require('../index');

describe('Test AES CBC Encryption', () => {
  const key128 = 'abc$#128djdyAgbj';
  const key192 = 'abc$#128djdyAgbjau&YAnmc';
  const key256 = 'abc$#128djdyAgbjau&YAnmcbagryt5x';

  it('should throw error if encrypted data not object or string', () => {
    const expected = 1234567890;

    const encryptedData = () => {
      aesEncryption.encryptWithAes128Cbc(key128, expected);
    };

    assert.throws(encryptedData, Error);
  });

  it('should throw error if decrypted data not object or string', () => {
    const expected = 1234567890;

    const decryptedData = () => {
      aesEncryption.decryptWithAes128Cbc(key128, expected);
    };

    assert.throws(decryptedData, Error);
  });

  it('should equal data from encryption and decryption with Aes128Cbc', () => {
    const expected = 'eyJhbGdvcml0aG0iOiJITUFDLVNIQTI1NiIsImV4cGlyZXMiOjEyNzk3NDYwMDAsIm9hdXRoX3Rva2VuIjoiMjk1NjY2Njk1MDY0fDIuRXpwem5IRVhZWkJVZmhGQ2l4ZzYzUV9fLjM2MDAuMTI3OTc0NjAwMC0xMDAwMDA0ODMyNzI5MjN8LXJ6U1pnRVBJTktaYnJnX1VNUUNhRzlNdEY4LiIsInVzZXJfaWQiOiIxMDAwMDA0ODMyNzI5MjMifQ';

    const encryptedData = aesEncryption.encryptWithAes128Cbc(key128, expected);

    const decryptedData = aesEncryption.decryptWithAes128Cbc(key128, encryptedData);

    assert.equal(expected, decryptedData);
  });

  it('should equal data from encryption and decryption with Aes192Cbc', () => {
    const expected = 'eyJhbGdvcml0aG0iOiJITUFDLVNIQTI1NiIsImV4cGlyZXMiOjEyNzk3NDYwMDAsIm9hdXRoX3Rva2VuIjoiMjk1NjY2Njk1MDY0fDIuRXpwem5IRVhZWkJVZmhGQ2l4ZzYzUV9fLjM2MDAuMTI3OTc0NjAwMC0xMDAwMDA0ODMyNzI5MjN8LXJ6U1pnRVBJTktaYnJnX1VNUUNhRzlNdEY4LiIsInVzZXJfaWQiOiIxMDAwMDA0ODMyNzI5MjMifQ';

    const encryptedData = aesEncryption.encryptWithAes192Cbc(key192, expected);

    const decryptedData = aesEncryption.decryptWithAes192Cbc(key192, encryptedData);

    assert.equal(expected, decryptedData);
  });

  it('should equal data from encryption and decryption with Aes256Cbc', () => {
    const expected = 'eyJhbGdvcml0aG0iOiJITUFDLVNIQTI1NiIsImV4cGlyZXMiOjEyNzk3NDYwMDAsIm9hdXRoX3Rva2VuIjoiMjk1NjY2Njk1MDY0fDIuRXpwem5IRVhZWkJVZmhGQ2l4ZzYzUV9fLjM2MDAuMTI3OTc0NjAwMC0xMDAwMDA0ODMyNzI5MjN8LXJ6U1pnRVBJTktaYnJnX1VNUUNhRzlNdEY4LiIsInVzZXJfaWQiOiIxMDAwMDA0ODMyNzI5MjMifQ';

    const encryptedData = aesEncryption.encryptWithAes256Cbc(key256, expected);

    const decryptedData = aesEncryption.decryptWithAes256Cbc(key256, encryptedData);

    assert.equal(expected, decryptedData);
  });
});

describe('Test AES GCM Encryption', () => {
  const key128 = 'abc$#128djdyAgbj';
  const key192 = 'abc$#128djdyAgbjau&YAnmc';
  const key256 = 'abc$#128djdyAgbjau&YAnmcbagryt5x';

  it('should equal data from encryption and decryption with Aes128Gcm', () => {
    const expected = 'eyJhbGdvcml0aG0iOiJITUFDLVNIQTI1NiIsImV4cGlyZXMiOjEyNzk3NDYwMDAsIm9hdXRoX3Rva2VuIjoiMjk1NjY2Njk1MDY0fDIuRXpwem5IRVhZWkJVZmhGQ2l4ZzYzUV9fLjM2MDAuMTI3OTc0NjAwMC0xMDAwMDA0ODMyNzI5MjN8LXJ6U1pnRVBJTktaYnJnX1VNUUNhRzlNdEY4LiIsInVzZXJfaWQiOiIxMDAwMDA0ODMyNzI5MjMifQ';

    const encryptedData = aesEncryption.encryptWithAes128Gcm(key128, expected);

    const decryptedData = aesEncryption.decryptWithAes128Gcm(key128, encryptedData);

    assert.equal(expected, decryptedData);
  });

  it('should equal data from encryption and decryption with Aes192Gcm', () => {
    const expected = 'eyJhbGdvcml0aG0iOiJITUFDLVNIQTI1NiIsImV4cGlyZXMiOjEyNzk3NDYwMDAsIm9hdXRoX3Rva2VuIjoiMjk1NjY2Njk1MDY0fDIuRXpwem5IRVhZWkJVZmhGQ2l4ZzYzUV9fLjM2MDAuMTI3OTc0NjAwMC0xMDAwMDA0ODMyNzI5MjN8LXJ6U1pnRVBJTktaYnJnX1VNUUNhRzlNdEY4LiIsInVzZXJfaWQiOiIxMDAwMDA0ODMyNzI5MjMifQ';

    const encryptedData = aesEncryption.encryptWithAes192Gcm(key192, expected);

    const decryptedData = aesEncryption.decryptWithAes192Gcm(key192, encryptedData);

    assert.equal(expected, decryptedData);
  });

  it('should equal data from encryption and decryption with Aes256Gcm', () => {
    const expected = 'eyJhbGdvcml0aG0iOiJITUFDLVNIQTI1NiIsImV4cGlyZXMiOjEyNzk3NDYwMDAsIm9hdXRoX3Rva2VuIjoiMjk1NjY2Njk1MDY0fDIuRXpwem5IRVhZWkJVZmhGQ2l4ZzYzUV9fLjM2MDAuMTI3OTc0NjAwMC0xMDAwMDA0ODMyNzI5MjN8LXJ6U1pnRVBJTktaYnJnX1VNUUNhRzlNdEY4LiIsInVzZXJfaWQiOiIxMDAwMDA0ODMyNzI5MjMifQ';

    const encryptedData = aesEncryption.encryptWithAes256Gcm(key256, expected);

    const decryptedData = aesEncryption.decryptWithAes256Gcm(key256, encryptedData);

    assert.equal(expected, decryptedData);
  });
});

describe('Test AES CCM Encryption', () => {
  const key128 = 'abc$#128djdyAgbj';
  const key192 = 'abc$#128djdyAgbjau&YAnmc';
  const key256 = 'abc$#128djdyAgbjau&YAnmcbagryt5x';

  it('should equal data from encryption and decryption with Aes128Ccm', () => {
    const expected = 'eyJhbGdvcml0aG0iOiJITUFDLVNIQTI1NiIsImV4cGlyZXMiOjEyNzk3NDYwMDAsIm9hdXRoX3Rva2VuIjoiMjk1NjY2Njk1MDY0fDIuRXpwem5IRVhZWkJVZmhGQ2l4ZzYzUV9fLjM2MDAuMTI3OTc0NjAwMC0xMDAwMDA0ODMyNzI5MjN8LXJ6U1pnRVBJTktaYnJnX1VNUUNhRzlNdEY4LiIsInVzZXJfaWQiOiIxMDAwMDA0ODMyNzI5MjMifQ';

    const encryptedData = aesEncryption.encryptWithAes128Ccm(key128, expected);

    const decryptedData = aesEncryption.decryptWithAes128Ccm(key128, encryptedData);

    assert.equal(expected, decryptedData);
  });

  it('should equal data from encryption and decryption with Aes192Ccm', () => {
    const expected = 'eyJhbGdvcml0aG0iOiJITUFDLVNIQTI1NiIsImV4cGlyZXMiOjEyNzk3NDYwMDAsIm9hdXRoX3Rva2VuIjoiMjk1NjY2Njk1MDY0fDIuRXpwem5IRVhZWkJVZmhGQ2l4ZzYzUV9fLjM2MDAuMTI3OTc0NjAwMC0xMDAwMDA0ODMyNzI5MjN8LXJ6U1pnRVBJTktaYnJnX1VNUUNhRzlNdEY4LiIsInVzZXJfaWQiOiIxMDAwMDA0ODMyNzI5MjMifQ';

    const encryptedData = aesEncryption.encryptWithAes192Ccm(key192, expected);

    const decryptedData = aesEncryption.decryptWithAes192Ccm(key192, encryptedData);

    assert.equal(expected, decryptedData);
  });

  it('should equal data from encryption and decryption with Aes256Ccm', () => {
    const expected = 'eyJhbGdvcml0aG0iOiJITUFDLVNIQTI1NiIsImV4cGlyZXMiOjEyNzk3NDYwMDAsIm9hdXRoX3Rva2VuIjoiMjk1NjY2Njk1MDY0fDIuRXpwem5IRVhZWkJVZmhGQ2l4ZzYzUV9fLjM2MDAuMTI3OTc0NjAwMC0xMDAwMDA0ODMyNzI5MjN8LXJ6U1pnRVBJTktaYnJnX1VNUUNhRzlNdEY4LiIsInVzZXJfaWQiOiIxMDAwMDA0ODMyNzI5MjMifQ';

    const encryptedData = aesEncryption.encryptWithAes256Ccm(key256, expected);

    const decryptedData = aesEncryption.decryptWithAes256Ccm(key256, encryptedData);

    assert.equal(expected, decryptedData);
  });
});

describe('Test AES OCB Encryption', () => {
  const key128 = 'abc$#128djdyAgbj';
  const key192 = 'abc$#128djdyAgbjau&YAnmc';
  const key256 = 'abc$#128djdyAgbjau&YAnmcbagryt5x';

  it('should equal data from encryption and decryption with Aes128Ocb', () => {
    const expected = 'eyJhbGdvcml0aG0iOiJITUFDLVNIQTI1NiIsImV4cGlyZXMiOjEyNzk3NDYwMDAsIm9hdXRoX3Rva2VuIjoiMjk1NjY2Njk1MDY0fDIuRXpwem5IRVhZWkJVZmhGQ2l4ZzYzUV9fLjM2MDAuMTI3OTc0NjAwMC0xMDAwMDA0ODMyNzI5MjN8LXJ6U1pnRVBJTktaYnJnX1VNUUNhRzlNdEY4LiIsInVzZXJfaWQiOiIxMDAwMDA0ODMyNzI5MjMifQ';

    const encryptedData = aesEncryption.encryptWithAes128Ocb(key128, expected);

    const decryptedData = aesEncryption.decryptWithAes128Ocb(key128, encryptedData);

    assert.equal(expected, decryptedData);
  });

  it('should equal data from encryption and decryption with Aes192Ocb', () => {
    const expected = 'eyJhbGdvcml0aG0iOiJITUFDLVNIQTI1NiIsImV4cGlyZXMiOjEyNzk3NDYwMDAsIm9hdXRoX3Rva2VuIjoiMjk1NjY2Njk1MDY0fDIuRXpwem5IRVhZWkJVZmhGQ2l4ZzYzUV9fLjM2MDAuMTI3OTc0NjAwMC0xMDAwMDA0ODMyNzI5MjN8LXJ6U1pnRVBJTktaYnJnX1VNUUNhRzlNdEY4LiIsInVzZXJfaWQiOiIxMDAwMDA0ODMyNzI5MjMifQ';

    const encryptedData = aesEncryption.encryptWithAes192Ocb(key192, expected);

    const decryptedData = aesEncryption.decryptWithAes192Ocb(key192, encryptedData);

    assert.equal(expected, decryptedData);
  });

  it('should equal data from encryption and decryption with Aes256Ocb', () => {
    const expected = 'eyJhbGdvcml0aG0iOiJITUFDLVNIQTI1NiIsImV4cGlyZXMiOjEyNzk3NDYwMDAsIm9hdXRoX3Rva2VuIjoiMjk1NjY2Njk1MDY0fDIuRXpwem5IRVhZWkJVZmhGQ2l4ZzYzUV9fLjM2MDAuMTI3OTc0NjAwMC0xMDAwMDA0ODMyNzI5MjN8LXJ6U1pnRVBJTktaYnJnX1VNUUNhRzlNdEY4LiIsInVzZXJfaWQiOiIxMDAwMDA0ODMyNzI5MjMifQ';

    const encryptedData = aesEncryption.encryptWithAes256Ocb(key256, expected);

    const decryptedData = aesEncryption.decryptWithAes256Ocb(key256, encryptedData);

    assert.equal(expected, decryptedData);
  });
});
