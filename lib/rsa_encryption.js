const { publicEncrypt, privateDecrypt, constants } = require('crypto');
const { Buffer } = require('buffer');
const alg = require('./alg');

/**
 * RSA Encryption
 * @param publicKey {RsaPublicKey}
 * @param digest {String}
 * @param data {Buffer}
 * @returns {Buffer}
 */
const encrypt = (publicKey, digest, data) => {
    if (!Buffer.isBuffer(data)) {
        throw new Error('data param should be buffer');
    }

    const encryptedData = publicEncrypt({
        key: publicKey,
        oaepHash: digest,
        padding: constants.RSA_PKCS1_OAEP_PADDING
    }, data);

    return encryptedData;
};

/**
 * @param publicKey {RsaPublicKey}
 * @param data {Buffer}
 * @returns {Buffer}
 */
exports.encryptWithOaepMd5 = (publicKey, data) => {
    return encrypt(publicKey, alg.MD5_DIGEST, data);
};

/**
 * @param publicKey {RsaPublicKey}
 * @param data {Buffer}
 * @returns {Buffer}
 */
exports.encryptWithOaepSha1 = (publicKey, data) => {
    return encrypt(publicKey, alg.SHA1_DIGEST, data);
};

/**
 * @param publicKey {RsaPublicKey}
 * @param data {Buffer}
 * @returns {Buffer}
 */
exports.encryptWithOaepSha256 = (publicKey, data) => {
    return encrypt(publicKey, alg.SHA256_DIGEST, data);
};

/**
 * @param publicKey {RsaPublicKey}
 * @param data {Buffer}
 * @returns {Buffer}
 */
exports.encryptWithOaepSha384 = (publicKey, data) => {
    return encrypt(publicKey, alg.SHA384_DIGEST, data);
};

/**
 * @param publicKey {RsaPublicKey}
 * @param data {Buffer}
 * @returns {Buffer}
 */
exports.encryptWithOaepSha512 = (publicKey, data) => {
    return encrypt(publicKey, alg.SHA512_DIGEST, data);
};

/**
 * RSA Decryption
 * @param privateKey {RsaPrivateKey}
 * @param digest {String}
 * @param data {Buffer}
 * @returns {Buffer}
 */
const decrypt = (privateKey, digest, data) => {
    if (!Buffer.isBuffer(data)) {
        throw new Error('data param should be buffer');
    }

    const decryptedData = privateDecrypt({
        key: privateKey,
        oaepHash: digest,
        padding: constants.RSA_PKCS1_OAEP_PADDING
    }, data);

    return decryptedData;
};

/**
 * @param privateKey {RsaPrivateKey}
 * @param encryptedData {Buffer}
 * @returns {Buffer}
 */
exports.decryptWithOaepMd5 = (privateKey, encryptedData) => {
    return decrypt(privateKey, alg.MD5_DIGEST, encryptedData);
};

/**
 * @param privateKey {RsaPrivateKey}
 * @param encryptedData {Buffer}
 * @returns {Buffer}
 */
exports.decryptWithOaepSha1 = (privateKey, encryptedData) => {
    return decrypt(privateKey, alg.SHA1_DIGEST, encryptedData);
};

/**
 * @param privateKey {RsaPrivateKey}
 * @param encryptedData {Buffer}
 * @returns {Buffer}
 */
exports.decryptWithOaepSha256 = (privateKey, encryptedData) => {
    return decrypt(privateKey, alg.SHA256_DIGEST, encryptedData);
};

/**
 * @param privateKey {RsaPrivateKey}
 * @param encryptedData {Buffer}
 * @returns {Buffer}
 */
exports.decryptWithOaepSha384 = (privateKey, encryptedData) => {
    return decrypt(privateKey, alg.SHA384_DIGEST, encryptedData);
};


/**
 * @param privateKey {RsaPrivateKey}
 * @param encryptedData {Buffer}
 * @returns {Buffer}
 */
exports.decryptWithOaepSha512 = (privateKey, encryptedData) => {
    return decrypt(privateKey, alg.SHA512_DIGEST, encryptedData);
};
