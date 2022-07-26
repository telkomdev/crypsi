const { publicEncrypt, privateDecrypt, constants } = require('crypto');
const alg = require('./alg');
const { checkBuffer } = require('./common');

/**
 * @param fnEncryptDecrypt {function}
 * @param key {Buffer | RsaPublicKey | RsaPrivateKey}
 * @param digest {string}
 * @param data {string | Buffer}
 * @return {Buffer | Error}
 */
const commonEncryptDecrypt = (fnEncryptDecrypt, key, digest, data) => {
  checkBuffer(data);
  const options = {
    key,
    oaepHash: digest,
    padding: constants.RSA_PKCS1_OAEP_PADDING,
  };
  return fnEncryptDecrypt(options, data);
};

/**
 * RSA Encryption
 * @param publicKey {Buffer | RsaPublicKey}
 * @param digest {string}
 * @param data {Buffer}
 * @returns {Buffer | Error}
 */
const encrypt = (publicKey, digest, data) => commonEncryptDecrypt(
  publicEncrypt,
  publicKey,
  digest,
  data,
);

/**
 * @param publicKey {Buffer | RsaPublicKey}
 * @param data {Buffer}
 * @returns {Buffer}
 */
exports.encryptWithOaepMd5 = (publicKey, data) => encrypt(
  publicKey,
  alg.MD5_DIGEST,
  data,
);

/**
 * @param publicKey {Buffer | RsaPublicKey}
 * @param data {Buffer}
 * @returns {Buffer}
 */
exports.encryptWithOaepSha1 = (publicKey, data) => encrypt(
  publicKey,
  alg.SHA1_DIGEST,
  data,
);

/**
 * @param publicKey {Buffer | RsaPublicKey}
 * @param data {Buffer}
 * @returns {Buffer}
 */
exports.encryptWithOaepSha256 = (publicKey, data) => encrypt(
  publicKey,
  alg.SHA256_DIGEST,
  data,
);

/**
 * @param publicKey {Buffer | RsaPublicKey}
 * @param data {Buffer}
 * @returns {Buffer}
 */
exports.encryptWithOaepSha384 = (publicKey, data) => encrypt(
  publicKey,
  alg.SHA384_DIGEST,
  data,
);

/**
 * @param publicKey {Buffer | RsaPublicKey}
 * @param data {Buffer}
 * @returns {Buffer}
 */
exports.encryptWithOaepSha512 = (publicKey, data) => encrypt(
  publicKey,
  alg.SHA512_DIGEST,
  data,
);

/**
 * RSA Decryption
 * @param privateKey {Buffer | RsaPrivateKey}
 * @param digest {string}
 * @param data {string | Buffer}
 * @returns {Buffer | Error}
 */
const decrypt = (privateKey, digest, data) => commonEncryptDecrypt(
  privateDecrypt,
  privateKey,
  digest,
  data,
);

/**
 * @param privateKey {Buffer | RsaPrivateKey}
 * @param encryptedData {Buffer}
 * @returns {Buffer}
 */
exports.decryptWithOaepMd5 = (privateKey, encryptedData) => decrypt(
  privateKey,
  alg.MD5_DIGEST,
  encryptedData,
);

/**
 * @param privateKey {Buffer | RsaPrivateKey}
 * @param encryptedData {Buffer}
 * @returns {Buffer}
 */
exports.decryptWithOaepSha1 = (privateKey, encryptedData) => decrypt(
  privateKey,
  alg.SHA1_DIGEST,
  encryptedData,
);

/**
 * @param privateKey {Buffer | RsaPrivateKey}
 * @param encryptedData {Buffer}
 * @returns {Buffer}
 */
exports.decryptWithOaepSha256 = (privateKey, encryptedData) => decrypt(
  privateKey,
  alg.SHA256_DIGEST,
  encryptedData,
);

/**
 * @param privateKey {Buffer | RsaPrivateKey}
 * @param encryptedData {Buffer}
 * @returns {Buffer}
 */
exports.decryptWithOaepSha384 = (privateKey, encryptedData) => decrypt(
  privateKey,
  alg.SHA384_DIGEST,
  encryptedData,
);

/**
 * @param privateKey {Buffer | RsaPrivateKey}
 * @param encryptedData {Buffer}
 * @returns {Buffer}
 */
exports.decryptWithOaepSha512 = (privateKey, encryptedData) => decrypt(
  privateKey,
  alg.SHA512_DIGEST,
  encryptedData,
);
