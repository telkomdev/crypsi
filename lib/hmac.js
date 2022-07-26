const { createHmac } = require('crypto');
const alg = require('./alg');
const keyUtil = require('./key_util');

/**
 * HMAC digest
 * @param alg {string}
 * @param key {Buffer | KeyObject}
 * @param datas {string | Buffer}
 * @returns {string}
 */
const digest = (alg, key, datas) => {
    const hmac = createHmac(alg, key)
    for (const data of datas) {
        hmac.update(data);
    }

    return hmac.digest('hex');
};

/**
 * @param key {Buffer | KeyObject}
 * @param datas {string | Buffer}
 * @returns {string}
 */
exports.md5 = (key, ...datas) => {
    if (key.length < keyUtil.MIN_CUSTOM_KEY_LEN) {
        throw new Error("key cannot less than " + keyUtil.MIN_CUSTOM_KEY_LEN);
    }

    return digest(alg.MD5_DIGEST, key, datas);
};

/**
 * @param key {Buffer | KeyObject}
 * @param datas {string | Buffer}
 * @return {string}
 */
exports.sha1 = (key, ...datas) => {
    if (key.length < keyUtil.MIN_CUSTOM_KEY_LEN) {
        throw new Error("key cannot less than " + keyUtil.MIN_CUSTOM_KEY_LEN);
    }

    return digest(alg.SHA1_DIGEST, key, datas);
};

/**
 * @param key {Buffer | KeyObject}
 * @param datas {string | Buffer}
 * @return {string}
 */
exports.sha256 = (key, ...datas) => {
    if (key.length < keyUtil.MIN_CUSTOM_KEY_LEN) {
        throw new Error("key cannot less than " + keyUtil.MIN_CUSTOM_KEY_LEN);
    }

    return digest(alg.SHA256_DIGEST, key, datas);
};

/**
 * @param key {Buffer | KeyObject}
 * @param datas {string | Buffer}
 * @return {string}
 */
exports.sha384 = (key, ...datas) => {
    if (key.length < keyUtil.MIN_CUSTOM_KEY_LEN) {
        throw new Error("key cannot less than " + keyUtil.MIN_CUSTOM_KEY_LEN);
    }

    return digest(alg.SHA384_DIGEST, key, datas);
};

/**
 * @param key {Buffer | KeyObject}
 * @param datas {string | Buffer}
 * @return {string}
 */
exports.sha512 = (key, ...datas) => {
    if (key.length < keyUtil.MIN_CUSTOM_KEY_LEN) {
        throw new Error("key cannot less than " + keyUtil.MIN_CUSTOM_KEY_LEN);
    }

    return digest(alg.SHA512_DIGEST, key, datas);
};
