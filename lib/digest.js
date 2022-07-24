const { createHash } = require('crypto');
const alg = require('./alg');

const digest = (alg, datas) => {
    const hash = createHash(alg)
    for (const data of datas) {
        hash.update(data);
    }

    return hash.digest('hex');
};

exports.md5 = (...datas) => {
    return digest(alg.MD5_DIGEST, datas);
};

exports.sha1 = (...datas) => {
    return digest(alg.SHA1_DIGEST, datas);
};

exports.sha256 = (...datas) => {
    return digest(alg.SHA256_DIGEST, datas);
};

exports.sha384 = (...datas) => {
    return digest(alg.SHA384_DIGEST, datas);
};

exports.sha512 = (...datas) => {
    return digest(alg.SHA512_DIGEST, datas);
};