const { Buffer } = require('buffer');


/**
 * @param {string | Buffer} buffer
 * @returns {string}
 */
const bufferToString = (buffer) => {
  if (Buffer.isBuffer(buffer)) {
    return buffer.toString();
  }
  return buffer;
};


/**
 * @param {string | Buffer} buffer
 */
const checkBuffer = (buffer) => {
  if (!Buffer.isBuffer(buffer)) {
    throw new Error('data param should be buffer');
  }
};

module.exports = {
  checkBuffer,
  bufferToString,
};
