const {Buffer} = require("buffer");
/**
 * Convert buffer input to string
 * @param buffer {string | Buffer}
 * @return {string}
 */
const bufferToString = (buffer) => {
  if (Buffer.isBuffer(buffer)) {
    return buffer.toString();
  }
  return buffer;
}

/**
 * Check if input is valid buffer
 * @param buffer {Buffer}
 * @return {void | Error}
 */
const checkBuffer = (buffer) => {
  if (!Buffer.isBuffer(buffer)) {
    throw new Error('data param should be buffer');
  }
}

module.exports = {
  checkBuffer,
  bufferToString,
};
