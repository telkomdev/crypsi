const assert = require('assert');
const { Buffer } = require('buffer');
const fs = require('fs');
const { rsa, rsaEncryption } = require('../index');

describe('Test RSA Encryption', () => {
  it('should throw error if dat is not buffer', () => {
    const privateKeyData = fs.readFileSync('./test/testdata/private.key');
    const publicKeyData = fs.readFileSync('./test/testdata/public.key');

    const privateKey = rsa.loadPrivateKey(privateKeyData);
    const publicKey = rsa.loadPublicKey(publicKeyData);

    const expected = 'hello world';
    const encryptedData = () => {
      rsaEncryption.encryptWithOaepSha256(publicKey, expected);
    };

    assert.throws(encryptedData, Error);
  });

  it('should equal data from encryption and decryption with OaepSha256', () => {
    const privateKeyData = fs.readFileSync('./test/testdata/private.key');
    const publicKeyData = fs.readFileSync('./test/testdata/public.key');

    const privateKey = rsa.loadPrivateKey(privateKeyData);
    const publicKey = rsa.loadPublicKey(publicKeyData);

    const expected = 'hello world';
    const encryptedData = rsaEncryption.encryptWithOaepSha256(publicKey, Buffer.from(expected));

    const decryptedData = rsaEncryption.decryptWithOaepSha256(privateKey, encryptedData);

    const bufferEqual = Buffer.compare(Buffer.from(expected), decryptedData) === 0;
    assert.equal(true, bufferEqual);
  });

  it('should equal data from encryption and decryption with OaepMd5', () => {
    const privateKeyData = fs.readFileSync('./test/testdata/private.key');
    const publicKeyData = fs.readFileSync('./test/testdata/public.key');

    const privateKey = rsa.loadPrivateKey(privateKeyData);
    const publicKey = rsa.loadPublicKey(publicKeyData);

    const expected = 'hello world';
    const encryptedData = rsaEncryption.encryptWithOaepMd5(publicKey, Buffer.from(expected));

    const decryptedData = rsaEncryption.decryptWithOaepMd5(privateKey, encryptedData);

    const bufferEqual = Buffer.compare(Buffer.from(expected), decryptedData) === 0;
    assert.equal(true, bufferEqual);
  });

  it('should equal data from encryption and decryption with OaepSha1', () => {
    const privateKeyData = fs.readFileSync('./test/testdata/private.key');
    const publicKeyData = fs.readFileSync('./test/testdata/public.key');

    const privateKey = rsa.loadPrivateKey(privateKeyData);
    const publicKey = rsa.loadPublicKey(publicKeyData);

    const expected = 'hello world';
    const encryptedData = rsaEncryption.encryptWithOaepSha1(publicKey, Buffer.from(expected));

    const decryptedData = rsaEncryption.decryptWithOaepSha1(privateKey, encryptedData);

    const bufferEqual = Buffer.compare(Buffer.from(expected), decryptedData) === 0;
    assert.equal(true, bufferEqual);
  });

  it('should equal data from encryption and decryption with OaepSha384', () => {
    const privateKeyData = fs.readFileSync('./test/testdata/private.key');
    const publicKeyData = fs.readFileSync('./test/testdata/public.key');

    const privateKey = rsa.loadPrivateKey(privateKeyData);
    const publicKey = rsa.loadPublicKey(publicKeyData);

    const expected = 'hello world';
    const encryptedData = rsaEncryption.encryptWithOaepSha384(publicKey, Buffer.from(expected));

    const decryptedData = rsaEncryption.decryptWithOaepSha384(privateKey, encryptedData);

    const bufferEqual = Buffer.compare(Buffer.from(expected), decryptedData) === 0;
    assert.equal(true, bufferEqual);
  });

  it('should equal data from encryption and decryption with OaepSha512', () => {
    const privateKeyData = fs.readFileSync('./test/testdata/private.key');
    const publicKeyData = fs.readFileSync('./test/testdata/public.key');

    const privateKey = rsa.loadPrivateKey(privateKeyData);
    const publicKey = rsa.loadPublicKey(publicKeyData);

    const expected = 'hello world';
    const encryptedData = rsaEncryption.encryptWithOaepSha512(publicKey, Buffer.from(expected));

    const decryptedData = rsaEncryption.decryptWithOaepSha512(privateKey, encryptedData);

    const bufferEqual = Buffer.compare(Buffer.from(expected), decryptedData) === 0;
    assert.equal(true, bufferEqual);
  });
});
