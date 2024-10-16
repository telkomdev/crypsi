const { createHash } = require('crypto');
const alg = require('./alg');


/**
 * Digest
 * @param {string} algorithm
 * @param {(string | Buffer)[]} datas
 * @returns {string}
 */
const digest = (algorithm, datas) => {
  const hash = createHash(algorithm);
  for (const data of datas) {
    hash.update(data);
  }

  return hash.digest('hex');
};

/**
 * @param {(string | Buffer)[]} datas
 * @return {string}
 */
exports.md5 = (...datas) => digest(alg.MD5_DIGEST, datas);

/**
 * @param {(string | Buffer)[]} datas
 * @return {string}
 */
exports.sha1 = (...datas) => digest(alg.SHA1_DIGEST, datas);

/**
 * @param {(string | Buffer)[]} datas
 * @return {string}
 */
exports.sha256 = (...datas) => digest(alg.SHA256_DIGEST, datas);

/**
 * @param {(string | Buffer)[]} datas
 * @return {string}
 */
exports.sha384 = (...datas) => digest(alg.SHA384_DIGEST, datas);

/**
 * @param {(string | Buffer)[]} datas
 * @return {string}
 */
exports.sha512 = (...datas) => digest(alg.SHA512_DIGEST, datas);
