var AWS = require("aws-sdk"),
    crypt = require("./crypt"),
    kms = new AWS.KMS(),
    s3 = new AWS.S3();

const metadataCipherAlgorithm = 'cipher-algorithm',
      metadataDecryptedEncoding = 'decrypted-encoding'
      metadataKmsKeyName = 'x-amz-key';

var   objects = {},
      objectTimestamps = {},
      cacheForMillis = 0;

exports.getObject = function(params, callback) {
  var cachedObject = getObjectFromCache(params);
  if (cacheForMillis > 0 && cachedObject && !isObjectStale(params)) {
    callback(null, cachedObject);
  } else {
    var encryptionContext = params.EncryptionContext;
    delete params.EncryptionContext;
    s3.getObject(params, function(err, objectData) {
      if (err) {
        callback(err, null);
      } else {
        var metadata = objectData.Metadata || {};
        var kmsKeyBase64 = metadata[metadataKmsKeyName];
        if (kmsKeyBase64) {
          var kmsKeyBuffer = new Buffer(kmsKeyBase64, 'base64');
          kms.decrypt({CiphertextBlob: kmsKeyBuffer, EncryptionContext: encryptionContext}, function(err, kmsData) {
            if (err) {
              callback(err, null);
            } else {
              var helper = new crypt.Helper(kmsData.Plaintext.toString('base64'), {algorithm: metadata[metadataCipherAlgorithm], decryptedEncoding: metadata[metadataDecryptedEncoding]});
              objectData.Body = helper.decrypt(objectData.Body.toString('utf-8'));
              delete objectData.Metadata[metadataKmsKeyName];
              delete objectData.Metadata[metadataCipherAlgorithm];
              delete objectData.Metadata[metadataDecryptedEncoding];
              putObjectIntoCache(params, objectData);
              callback(null, objectData);
            }
          });
        } else {
          putObjectIntoCache(params, objectData);
          callback(null, objectData);
        }
      }
    });
  }
}

exports.putObject = function(params, callback) {
  var kmsParams = params.KmsParams
  if (kmsParams && kmsParams.KeyId) {
    kms.generateDataKey(kmsParams, function(err, kmsData) {
      if (err) {
        callback(err, null);
      } else {
        var helper = new crypt.Helper(kmsData.Plaintext.toString('base64'), {algorithm: params.CipherAlgorithm, decryptedEncoding: params.DecryptedEncoding});
        params.Body = helper.encrypt(params.Body);
        params.Metadata = params.Metadata || {};
        params.Metadata[metadataKmsKeyName] = kmsData.CiphertextBlob.toString('base64');
        if (params.CipherAlgorithm) params.Metadata[metadataCipherAlgorithm] = params.CipherAlgorithm;
        if (params.DecryptedEncoding) params.Metadata[metadataDecryptedEncoding] = params.DecryptedEncoding;
        putObject(params, callback);
      }
    })
  } else {
    putObject(params, callback);
  }
}

exports.cacheFor = function(millis) {
  cacheForMillis = millis;
}

function getObjectFromCache(params) {
  if (objects[params.Bucket] && objects[params.Bucket][params.Key]) {
    return objects[params.Bucket][params.Key];
  }
}

function isObjectStale(params) {
  if (objectTimestamps[params.Bucket] && objectTimestamps[params.Bucket][params.Key]) {
    var d = objectTimestamps[params.Bucket][params.Key];
    d = new Date(d.getTime() + cacheForMillis);
    return d < (new Date());
  }
  return true;
}

function putObject(params, callback) {
  delete params.KmsParams;
  delete params.CipherAlgorithm;
  delete params.DecryptedEncoding;
  s3.putObject(params, callback);
}

function putObjectIntoCache(params, objectData) {
  if (!objects[params.Bucket]) objects[params.Bucket] = {};
  objects[params.Bucket][params.Key] = objectData;
  if (!objectTimestamps[params.Bucket]) objectTimestamps[params.Bucket] = {};
  objectTimestamps[params.Bucket][params.Key] = new Date();
}