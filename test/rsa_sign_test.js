const assert = require('assert');
const fs = require('fs');
const { rsa, rsaSign } = require('../index');

describe('Test RSA Digital Signature', () => {
  it('should valid signing and verifying data WithPSS md5', () => {
    const privateKeyData = fs.readFileSync('./test/testdata/private.key');
    const publicKeyData = fs.readFileSync('./test/testdata/public.key');

    const privateKey = rsa.loadPrivateKey(privateKeyData);
    const publicKey = rsa.loadPublicKey(publicKeyData);

    const data = 'hello world';
    const signature = rsaSign.signWithPSSMd5(privateKey, data);
    const signatureValid = rsaSign.verifyWithPSSMd5(publicKey, signature, data);

    const expected = true;
    assert.equal(expected, signatureValid);
  });

  it('should valid signing and verifying data WithPSS sha256', () => {
    const privateKeyData = fs.readFileSync('./test/testdata/private.key');
    const publicKeyData = fs.readFileSync('./test/testdata/public.key');

    const privateKey = rsa.loadPrivateKey(privateKeyData);
    const publicKey = rsa.loadPublicKey(publicKeyData);

    const data = 'hello world';
    const signature = rsaSign.signWithPSSSha256(privateKey, data);
    const signatureValid = rsaSign.verifyWithPSSSha256(publicKey, signature, data);

    const expected = true;
    assert.equal(expected, signatureValid);
  });

  it('should valid signing and verifying data WithPSS sha1', () => {
    const privateKeyData = fs.readFileSync('./test/testdata/private.key');
    const publicKeyData = fs.readFileSync('./test/testdata/public.key');

    const privateKey = rsa.loadPrivateKey(privateKeyData);
    const publicKey = rsa.loadPublicKey(publicKeyData);

    const data = 'hello world';
    const signature = rsaSign.signWithPSSSha1(privateKey, data);
    const signatureValid = rsaSign.verifyWithPSSSha1(publicKey, signature, data);

    const expected = true;
    assert.equal(expected, signatureValid);
  });

  it('should valid signing and verifying data WithPSS sha384', () => {
    const privateKeyData = fs.readFileSync('./test/testdata/private.key');
    const publicKeyData = fs.readFileSync('./test/testdata/public.key');

    const privateKey = rsa.loadPrivateKey(privateKeyData);
    const publicKey = rsa.loadPublicKey(publicKeyData);

    const data = 'hello world';
    const signature = rsaSign.signWithPSSSha384(privateKey, data);
    const signatureValid = rsaSign.verifyWithPSSSha384(publicKey, signature, data);

    const expected = true;
    assert.equal(expected, signatureValid);
  });

  it('should valid signing and verifying data WithPSS sha512', () => {
    const privateKeyData = fs.readFileSync('./test/testdata/private.key');
    const publicKeyData = fs.readFileSync('./test/testdata/public.key');

    const privateKey = rsa.loadPrivateKey(privateKeyData);
    const publicKey = rsa.loadPublicKey(publicKeyData);

    const data = 'hello world';
    const signature = rsaSign.signWithPSSSha512(privateKey, data);
    const signatureValid = rsaSign.verifyWithPSSSha512(publicKey, signature, data);

    const expected = true;
    assert.equal(expected, signatureValid);
  });
});
