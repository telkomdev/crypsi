const { generateKey, randomFillSync } = require('crypto');
const { Buffer } = require('buffer');

exports.KEY_SIZE_1KB = 1 << 10; // 1024
exports.KEY_SIZE_2KB = 1 << 11; // 2048
exports.KEY_SIZE_4KB = 1 << 12; // 4096

exports.HMAC_MINIMUM_KEY_SIZE = 8;
exports.AES_128_KEY_SIZE = 16;
exports.AES_192_KEY_SIZE = 24;
exports.AES_256_KEY_SIZE = 32;

exports.MIN_CUSTOM_KEY_LEN = 32;

exports.IV_SIZE = 12;

exports.generateRandomIV = (size = this.IV_SIZE) => {
    const buf = Buffer.alloc(size);
    return randomFillSync(buf).toString('hex');
};