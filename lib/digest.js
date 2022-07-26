const { createHash } = require('crypto');
const alg = require('./alg');

/**
 * @param alg {string}
 * @param datas {string | Buffer}
 * @return {string}
 */
const digest = (alg, datas) => {
    const hash = createHash(alg)
    for (const data of datas) {
        hash.update(data);
    }

    return hash.digest('hex');
};

/**
 * @param datas {string | Buffer}
 * @return {string}
 */
exports.md5 = (...datas) => {
    return digest(alg.MD5_DIGEST, datas);
};

/**
 * @param datas {string | Buffer}
 * @return {string}
 */
exports.sha1 = (...datas) => {
    return digest(alg.SHA1_DIGEST, datas);
};

/**
 * @param datas {string | Buffer}
 * @return {string}
 */
exports.sha256 = (...datas) => {
    return digest(alg.SHA256_DIGEST, datas);
};

/**
 * @param datas {string | Buffer}
 * @return {string}
 */
exports.sha384 = (...datas) => {
    return digest(alg.SHA384_DIGEST, datas);
};

/**
 * @param datas {string | Buffer}
 * @return {string}
 */
exports.sha512 = (...datas) => {
    return digest(alg.SHA512_DIGEST, datas);
};
