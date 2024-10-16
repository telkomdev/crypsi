const { createHmac } = require('crypto');
const alg = require('./alg');
const keyUtil = require('./key_util');


/**
 * Hmac digest
 * @param {string} algorithm
 * @param {string | Buffer} key
 * @param {(string | Buffer)[]} datas
 * @returns {string}
 */
const digest = (algorithm, key, datas) => {
  const hmac = createHmac(algorithm, key);
  for (const data of datas) {
    hmac.update(data);
  }

  return hmac.digest('hex');
};


/**
 * @param {string} algorithm
 * @param {string | Buffer} key
 * @param {(string | Buffer)[]} datas
 * @returns {string}
 */
const commonGenerateDigest = (algorithm, key, datas) => {
  keyUtil.checkKeyInput(key);

  return digest(algorithm, key, datas);
};

/**
 * @param {string | Buffer} key
 * @param {(string | Buffer)[]} datas
 * @returns {string}
 */
exports.md5 = (key, ...datas) => commonGenerateDigest(alg.MD5_DIGEST, key, datas);

/**
 * @param {string | Buffer} key
 * @param {(string | Buffer)[]} datas
 * @returns {string}
 */
exports.sha1 = (key, ...datas) => commonGenerateDigest(alg.SHA1_DIGEST, key, datas);

/**
 * @param {string | Buffer} key
 * @param {(string | Buffer)[]} datas
 * @returns {string}
 */
exports.sha256 = (key, ...datas) => commonGenerateDigest(alg.SHA256_DIGEST, key, datas);

/**
 * @param {string | Buffer} key
 * @param {(string | Buffer)[]} datas
 * @returns {string}
 */
exports.sha384 = (key, ...datas) => commonGenerateDigest(alg.SHA384_DIGEST, key, datas);

/**
 * @param {string | Buffer} key
 * @param {(string | Buffer)[]} datas
 * @returns {string}
 */
exports.sha512 = (key, ...datas) => commonGenerateDigest(alg.SHA512_DIGEST, key, datas);
