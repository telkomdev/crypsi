const assert = require('assert');
const { hmac } = require('../index');

describe('Test Keyed-Hash Message Authentication Code (HMAC) ', () => {
  const key = 'abc$#128djdyAgbjau&YAnmcbagryt5x';

  it('should equal to exptected when Hmac with md5', () => {
    const expected = 'd213b2e973c1a5d704255518af6d073c';

    const data = 'wuriyanto';
    const actual = hmac.md5(key, data);
    assert.equal(actual, expected);
  });

  it('should equal to exptected when Hmac with sha1', () => {
    const expected = '69fa82ae1f1398e6e570a4780df908adad3998df';

    const data = 'wuriyanto';
    const actual = hmac.sha1(key, data);
    assert.equal(actual, expected);
  });

  it('should equal to exptected when Hmac with sha256', () => {
    const expected = '9f46bcc1bdc24ff2d4b6f811c1dd7e053089e515b0525c2b2a7ff25c28eb4240';

    const data = 'wuriyanto';
    const actual = hmac.sha256(key, data);
    assert.equal(actual, expected);
  });

  it('should equal to exptected when Hmac with sha384', () => {
    const expected = '69b5b98267f760b5dc39cde790adc89358c9a59d7eac7e76c5a9e7acb9c037d0293810251de16afdf96adcbf9e512ed4';

    const data = 'wuriyanto';
    const actual = hmac.sha384(key, data);
    assert.equal(actual, expected);
  });

  it('should equal to exptected when Hmac with sha512', () => {
    const expected = '0084af8c8d831581b30f3ef2a250355bb04f2b2ca632d656ab8dce2b34692e5238ed19f7638070a115196dd928dfff3717dddf9d072ae9c26716c8faa11a25f8';

    const data = 'wuriyanto';
    const actual = hmac.sha512(key, data);
    assert.equal(actual, expected);
  });
});
