var assert = require('assert'),
    AWS = require('aws-sdk'),
    crypt = require('../../lib/crypt'),
    sinon = require('sinon');
var s3Enc;

describe('node-s3-encryption-client', function() {
  var kms = {'decrypt': function(){}, 'generateDataKey': function(){}},
      s3 = {'getObject': function(){}, 'putObject': function(){}};

  before(function() {
    sinon.stub(AWS, 'KMS').returns(kms);
    sinon.stub(AWS, 'S3').returns(s3);
    delete require.cache[require.resolve('../../lib/main')];
    s3Enc = require('../../lib/main');
  });

  after(function() {
    AWS.KMS.restore();
    AWS.S3.restore();
  });

  describe('#getObject()', function() {
    beforeEach(function() {
      sinon
        .stub(kms, 'decrypt')
        .yields(null, {"Plaintext": new Buffer("123456", 'base64')});
    });

    afterEach(function() {
      kms.decrypt.restore();
      s3.getObject.restore();
      s3Enc.cacheFor(0);
    });

    it('should decrypt content when a key is present', function() {
      var helper = new crypt.Helper("12345w==");
      sinon
        .stub(s3, 'getObject')
        .yields(null, {"Body": new Buffer(helper.encrypt("foo"), 'utf-8'), "Metadata": {"x-amz-key": "encrypted-key"}});
      s3Enc.getObject({
        Bucket: "test-bucket",
        Key: "test-key"
      }, function(err, data) {
        assert.equal(err, null);
        assert.equal(data.Body, "foo");
        assert.deepEqual(data.Metadata, {});
      });
    });

    it('should use the cipher algorithm when present', function() {
      var helper = new crypt.Helper("12345w==", {algorithm: "des-cbc"});
      sinon
        .stub(s3, 'getObject')
        .yields(null, {"Body": new Buffer(helper.encrypt("foo"), 'utf-8'), "Metadata": {"x-amz-key": "encrypted-key", "cipher-algorithm": "des-cbc"}});
      s3Enc.getObject({
        Bucket: "test-bucket",
        Key: "test-key"
      }, function(err, data) {
        assert.equal(err, null);
        assert.equal(data.Body, "foo");
        assert.deepEqual(data.Metadata, {});
      });
    });

    it('should use the decrypted encoding when present', function() {
      var helper = new crypt.Helper("12345w==", {decryptedEncoding: "binary"});
      sinon
        .stub(s3, 'getObject')
        .yields(null, {"Body": new Buffer(helper.encrypt("foo"), 'utf-8'), "Metadata": {"x-amz-key": "encrypted-key", "decrypted-encoding": "binary"}});
      s3Enc.getObject({
        Bucket: "test-bucket",
        Key: "test-key"
      }, function(err, data) {
        assert.equal(err, null);
        assert.equal(data.Body, "foo");
        assert.deepEqual(data.Metadata, {});
      });
    });

    it('should pass the EncryptionContext to KMS when specified', function() {
      var helper = new crypt.Helper("12345w==");
      kms.decrypt.restore();
      var kmsstub = sinon.stub(kms, 'decrypt');
      kmsstub.withArgs({CiphertextBlob: new Buffer("encrypted-key", 'base64'), EncryptionContext: {"foo": "bar"}}).yields(null, {"Plaintext": new Buffer("123456", 'base64')});
      kmsstub.yields("Invalid args");
      var s3stub = sinon.stub(s3, 'getObject');
      s3stub.withArgs({Bucket: "test-bucket", Key: "test-key"}).yields(null, {"Body": new Buffer(helper.encrypt("foo"), 'utf-8'), "Metadata": {"x-amz-key": "encrypted-key"}});
      s3stub.yields("Invalid args");

      s3Enc.getObject({
        Bucket: "test-bucket",
        Key: "test-key",
        EncryptionContext: {"foo": "bar"}
      }, function(err, data) {
        assert.equal(err, null);
        assert.equal(data.Body, "foo");
        assert.deepEqual(data.Metadata, {});
      });
    });

    it('should remove encryption Metadata but not lose other Metadata when decrypting', function() {
      var helper = new crypt.Helper("12345w==");
      sinon
        .stub(s3, 'getObject')
        .yields(null, {"Body": new Buffer(helper.encrypt("foo"), 'utf-8'), "Metadata": {"x-amz-key": "encrypted-key", "foo": "bar"}});
      s3Enc.getObject({
        Bucket: "test-bucket",
        Key: "test-key"
      }, function(err, data) {
        assert.equal(err, null);
        assert.equal(data.Body, "foo");
        assert.deepEqual(data.Metadata, {"foo": "bar"});
      });
    });

    it('should not store encrypted values in the cache when timeout is zero', function() {
      var helper = new crypt.Helper("12345w==");
      sinon
        .stub(s3, 'getObject')
        .yields(null, {"Body": new Buffer(helper.encrypt("foo"), 'utf-8'), "Metadata": {"x-amz-key": "encrypted-key"}});
      s3Enc.getObject({
        Bucket: "test-bucket",
        Key: "test-key"
      }, function(err, data) {
        assert.equal(err, null);
        assert.equal(data.Body, "foo");
        assert.deepEqual(data.Metadata, {});
        s3.getObject.restore();
        sinon
          .stub(s3, 'getObject')
          .yields(new Error('err'), null);
        s3Enc.getObject({
          Bucket: "test-bucket",
          Key: "test-key"
        }, function(err, data) {
          assert.equal(err, "Error: err");
          assert.equal(data, null);
        });
      });
    });

    it('should store encrypted values in the cache when timeout is non-zero', function() {
      s3Enc.cacheFor(100);
      var helper = new crypt.Helper("12345w==");
      sinon
        .stub(s3, 'getObject')
        .yields(null, {"Body": new Buffer(helper.encrypt("foo"), 'utf-8'), "Metadata": {"x-amz-key": "encrypted-key"}});
      s3Enc.getObject({
        Bucket: "test-bucket",
        Key: "test-key"
      }, function(err, data) {
        assert.equal(err, null);
        assert.equal(data.Body, "foo");
        assert.deepEqual(data.Metadata, {});
        s3.getObject.restore();
        sinon
          .stub(s3, 'getObject')
          .yields(new Error('err'), null);
        s3Enc.getObject({
          Bucket: "test-bucket",
          Key: "test-key"
        }, function(err, data) {
          assert.equal(err, null);
          assert.equal(data.Body, "foo");
          assert.deepEqual(data.Metadata, {});
        });
      });
    });

    it('should invalidate encrypted values from the cache when non-zero timeout expires', function() {
      s3Enc.cacheFor(100);
      var helper = new crypt.Helper("12345w==");
      sinon
        .stub(s3, 'getObject')
        .yields(null, {"Body": new Buffer(helper.encrypt("foo"), 'utf-8'), "Metadata": {"x-amz-key": "encrypted-key"}});
      s3Enc.getObject({
        Bucket: "test-bucket",
        Key: "test-key"
      }, function(err, data) {
        assert.equal(err, null);
        assert.equal(data.Body, "foo");
        assert.deepEqual(data.Metadata, {});
        s3.getObject.restore();
        sinon
          .stub(s3, 'getObject')
          .yields(new Error('err'), null);
        var waitUntil = new Date(new Date().getTime() + 110);
        while(waitUntil > new Date()){}
        s3Enc.getObject({
          Bucket: "test-bucket",
          Key: "test-key"
        }, function(err, data) {
          assert.equal(err, "Error: err");
          assert.equal(data, null);
        });
      });
    });

    it('should not decrypt content when there is no key', function() {
      sinon
        .stub(s3, 'getObject')
        .yields(null, {"Body": new Buffer("foo", 'utf-8')});
      s3Enc.getObject({
        Bucket: "test-bucket",
        Key: "test-key"
      }, function(err, data) {
        assert.equal(err, null);
        assert.equal(data.Body, "foo");
      });
    });

    it('should pull unencrypted object from cache', function() {
      s3Enc.cacheFor(100);
      sinon
        .stub(s3, 'getObject')
        .yields(null, {"Body": new Buffer("foo", 'utf-8')});
      s3Enc.getObject({
        Bucket: "test-bucket",
        Key: "test-key"
      }, function(err, data) {
        assert.equal(err, null);
        assert.equal(data.Body, "foo");
        s3.getObject.restore();
        sinon
          .stub(s3, 'getObject')
          .yields(new Error('err'), null);
        var waitUntil = new Date(new Date().getTime() + 110);
        while(waitUntil > new Date()){}
        s3Enc.getObject({
          Bucket: "test-bucket",
          Key: "test-key"
        }, function(err, data) {
          assert.equal(err, "Error: err");
          assert.equal(data, null);
        });
      });
    });

    it('should invalidate unencrypted object from cache', function() {
      s3Enc.cacheFor(100);
      sinon
        .stub(s3, 'getObject')
        .yields(null, {"Body": new Buffer("foo", 'utf-8')});
      s3Enc.getObject({
        Bucket: "test-bucket",
        Key: "test-key"
      }, function(err, data) {
        assert.equal(err, null);
        assert.equal(data.Body, "foo");
        s3.getObject.restore();
        sinon
          .stub(s3, 'getObject')
          .yields(new Error('err'), null);
        s3Enc.getObject({
          Bucket: "test-bucket",
          Key: "test-key"
        }, function(err, data) {
          assert.equal(err, null);
          assert.equal(data.Body, "foo");
        });
      });
    });

    it('should pass the S3 failure through to the callback', function() {
      sinon
        .stub(s3, 'getObject')
        .yields({name: "Error", message: "S3 error"}, null);
      s3Enc.getObject({
        Bucket: "test-bucket",
        Key: "test-key"
      }, function(err, data) {
        assert.equal(data, null);
        assert.deepEqual(err, {name: "Error", message: "S3 error"});
      });
    });

    it('should pass the KMS failure through to the callback', function() {
      kms.decrypt.restore();
      sinon
        .stub(kms, 'decrypt')
        .yields({name: "Error", message: "KMS error"}, null);
      sinon
        .stub(s3, 'getObject')
        .yields(null, {"Body": new Buffer("invalid", 'utf-8'), "Metadata": {"x-amz-key": "encrypted-key", "foo": "bar"}});
      s3Enc.getObject({
        Bucket: "test-bucket",
        Key: "test-key"
      }, function(err, data) {
        assert.equal(data, null);
        assert.deepEqual(err, {name: "Error", message: "KMS error"});
      });
    });
  });

  describe('#putObject()', function() {
    beforeEach(function() {
      sinon
        .stub(kms, 'generateDataKey')
        .yields(null, {"Plaintext": new Buffer("123456", 'base64'), "CiphertextBlob": new Buffer("ciphertextblob", "base64")});
    });

    afterEach(function() {
      kms.generateDataKey.restore();
      s3.putObject.restore();
    });

    it('should not encrypt if KmsParams is missing', function() {
      var s3stub = sinon.stub(s3, 'putObject');
      s3stub.withArgs({
        Bucket: "test-bucket",
        Key: "test-key",
        Body: "foo"
      }).yields(null, {"ETag": "123456"});
      s3stub.yields("Invalid args");

      s3Enc.putObject({
        Bucket: "test-bucket",
        Key: "test-key",
        Body: "foo"
      }, function(err, data) {
        assert.equal(err, null);
        assert.deepEqual(data, {"ETag": "123456"});
      });
    });

    it('should not encrypt if KmsParams.KeyId is missing', function() {
      var s3stub = sinon.stub(s3, 'putObject');
      s3stub.withArgs({
        Bucket: "test-bucket",
        Key: "test-key",
        Body: "foo"
      }).yields(null, {"ETag": "123456"});
      s3stub.yields("Invalid args");

      s3Enc.putObject({
        Bucket: "test-bucket",
        Key: "test-key",
        Body: "foo",
        KmsParams: {
          EncryptionContext: {}
        }
      }, function(err, data) {
        assert.equal(err, null);
        assert.deepEqual(data, {"ETag": "123456"});
      });
    });

    it('should encrypt if KmsParams.KeyId is given', function() {
      var helper = new crypt.Helper("12345w==");
      var s3stub = sinon.stub(s3, 'putObject');
      s3stub.withArgs({
        Bucket: "test-bucket",
        Key: "test-key",
        Body: helper.encrypt("foo"),
        Metadata: {
          "x-amz-key": "ciphertextbloQ=="
        }
      }).yields(null, {"ETag": "123456"});
      s3stub.yields("Invalid args");

      s3Enc.putObject({
        Bucket: "test-bucket",
        Key: "test-key",
        Body: "foo",
        KmsParams: {
          KeyId: "alias/key-id"
        }
      }, function(err, data) {
        assert.equal(err, null);
        assert.deepEqual(data, {"ETag": "123456"});
      });
    });

    it('should encrypt with cipher algorithm if given', function() {
      var helper = new crypt.Helper("12345w==", {"algorithm": "des-cbc"});
      var s3stub = sinon.stub(s3, 'putObject');
      s3stub.withArgs({
        Bucket: "test-bucket",
        Key: "test-key",
        Body: helper.encrypt("foo"),
        Metadata: {
          "x-amz-key": "ciphertextbloQ==",
          "cipher-algorithm": "des-cbc"
        }
      }).yields(null, {"ETag": "123456"});
      s3stub.yields("Invalid args");

      s3Enc.putObject({
        Bucket: "test-bucket",
        Key: "test-key",
        Body: "foo",
        KmsParams: {
          KeyId: "alias/key-id"
        },
        CipherAlgorithm: "des-cbc"
      }, function(err, data) {
        assert.equal(err, null);
        assert.deepEqual(data, {"ETag": "123456"});
      });
    });

    it('should encrypt with decrypted encoding if given', function() {
      var helper = new crypt.Helper("12345w==", {"decryptedEncoding": "binary"});
      var s3stub = sinon.stub(s3, 'putObject');
      s3stub.withArgs({
        Bucket: "test-bucket",
        Key: "test-key",
        Body: helper.encrypt("foo"),
        Metadata: {
          "x-amz-key": "ciphertextbloQ==",
          "decrypted-encoding": "binary"
        }
      }).yields(null, {"ETag": "123456"});
      s3stub.yields("Invalid args");

      s3Enc.putObject({
        Bucket: "test-bucket",
        Key: "test-key",
        Body: "foo",
        KmsParams: {
          KeyId: "alias/key-id"
        },
        DecryptedEncoding: "binary"
      }, function(err, data) {
        assert.equal(err, null);
        assert.deepEqual(data, {"ETag": "123456"});
      });
    });

    it('should encrypt with EncondingContext if given', function() {
      var helper = new crypt.Helper("12345w==");
      var s3stub = sinon.stub(s3, 'putObject');
      s3stub.withArgs({
        Bucket: "test-bucket",
        Key: "test-key",
        Body: helper.encrypt("foo"),
        Metadata: {
          "x-amz-key": "ciphertextbloQ=="
        }
      }).yields(null, {"ETag": "123456"});
      s3stub.yields("Invalid args");
      kms.generateDataKey.restore();
      var kmsstub = sinon.stub(kms, 'generateDataKey');
      kmsstub.withArgs({KeyId: "alias/key-id", EncryptionContext: {"foo": "bar"}}).yields(null, {"Plaintext": new Buffer("123456", 'base64'), "CiphertextBlob": new Buffer("ciphertextblob", "base64")});
      kmsstub.yields("Invalid args");

      s3Enc.putObject({
        Bucket: "test-bucket",
        Key: "test-key",
        Body: "foo",
        KmsParams: {
          KeyId: "alias/key-id",
          EncryptionContext: {"foo": "bar"}
        }
      }, function(err, data) {
        assert.equal(err, null);
        assert.deepEqual(data, {"ETag": "123456"});
      });
    });

    it('should pass S3 failures through to the callback', function() {
      sinon
        .stub(s3, 'putObject')
        .yields({"name": "Error", "message": "S3 Error"}, null);

      s3Enc.putObject({
        Bucket: "test-bucket",
        Key: "test-key",
        Body: "foo"
      }, function(err, data) {
        assert.equal(data, null);
        assert.deepEqual(err, {"name": "Error", "message": "S3 Error"});
      });
    });

    it('should pass S3 failures through to the callback after encryption', function() {
      var s3stub = sinon
      .stub(s3, 'putObject')
      .yields({"name": "Error", "message": "S3 Error"}, null);
      kms.generateDataKey.restore();
      var kmsstub = sinon.stub(kms, 'generateDataKey');
      kmsstub.withArgs({KeyId: "alias/key-id", EncryptionContext: {"foo": "bar"}}).yields(null, {"Plaintext": new Buffer("123456", "base64"), "CiphertextBlob": new Buffer("ciphertextblob", "base64")});
      kmsstub.yields("Invalid args");

      s3Enc.putObject({
        Bucket: "test-bucket",
        Key: "test-key",
        Body: "foo",
        KmsParams: {
          KeyId: "alias/key-id",
          EncryptionContext: {"foo": "bar"}
        }
      }, function(err, data) {
        assert.equal(data, null);
        assert.deepEqual(err, {"name": "Error", "message": "S3 Error"});
      });
    });

    it('should pass KMS failures through to the callback', function() {
      sinon.stub(s3, 'putObject')
      kms.generateDataKey.restore();
      var kmsstub = sinon
      .stub(kms, 'generateDataKey')
      .yields({"name": "Error", "message": "KMS Error"}, null);

      s3Enc.putObject({
        Bucket: "test-bucket",
        Key: "test-key",
        Body: "foo",
        KmsParams: {
          KeyId: "alias/key-id"
        }
      }, function(err, data) {
        assert.equal(data, null);
        assert.deepEqual(err, {"name": "Error", "message": "KMS Error"});
      });
    });
  });
});
