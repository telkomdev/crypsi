const assert = require('assert');
const { digest } = require('../index');

describe('Test Digest (Hashing Algorithm)', () => {
  it('should equal to exptected when hashing with md5', () => {
    const expected = '60e1bc04fa194a343b50ce67f4afcff8';

    const data = 'wuriyanto';
    const actual = digest.md5(data);

    assert.equal(actual, expected);
  });

  it('should equal to exptected when hashing with sha1', () => {
    const expected = 'afd2bd72af0c346a2ab14d50746835d3ccd1dd5f';

    const data = 'wuriyanto';
    const actual = digest.sha1(data);

    assert.equal(actual, expected);
  });

  it('should equal to exptected when hashing with sha256', () => {
    const expected = '7da544fa170151239b9886c0c905736fe3e8b07e68aefaba0633272aee47af87';

    const data = 'wuriyanto';
    const actual = digest.sha256(data);

    assert.equal(actual, expected);
  });

  it('should equal to exptected when hashing with sha384', () => {
    const expected = '2bf236501ecea775cd0eac6da0632eb236e514f29c2aff06a42819fe3b1f3d5b8aefe8c1608a8f5a4d832090902f84a1';

    const data = 'wuriyanto';
    const actual = digest.sha384(data);

    assert.equal(actual, expected);
  });

  it('should equal to exptected when hashing with sha512', () => {
    const expected = '5adf884c57a5dc4f353bb08a138953e98320c35843ec86dd42e866e9111f39f502dd250a31f421c9eae8b0593540c30b4ecba6f7f5356632aeea308ee5a5a206';

    const data = 'wuriyanto';
    const actual = digest.sha512(data);

    assert.equal(actual, expected);
  });
});
