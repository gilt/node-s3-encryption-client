# node-s3-encryption-client [![Build Status](https://travis-ci.org/gilt/node-s3-encryption-client.svg?branch=master)](https://travis-ci.org/gilt/node-s3-encryption-client)
Node.js implementation of the KMS Envelope Encryption for AWS S3

The Amazon S3 Encryption Client (http://docs.aws.amazon.com/kms/latest/developerguide/services-s3.html#sse-client)
currently only exists for Java and Ruby. This library implements KMS envelope encryption
(http://docs.aws.amazon.com/kms/latest/developerguide/workflow.html) for Javascript, adding
an option to choose the cipher algorithm and the S3 objects encoding. It exposes getObject and putObject
from the AWS S3 client, with KMS encryption options for client-side encryption.


## Methods

### getObject
Functions exactly the same as http://docs.aws.amazon.com/AWSJavaScriptSDK/latest/AWS/S3.html#getObject-property,
except that it will transparently decrypt the object if a KMS key is present in its Metadata. Additional params
are as follows.

#### EncryptionContext
Same as the EncryptionContext property here: http://docs.aws.amazon.com/AWSJavaScriptSDK/latest/AWS/KMS.html#generateDataKey-property
Must be specified for decryption (i.e. getObject) if it was specified during encryption (i.e. putObject).


### putObject
Functions exactly the same as http://docs.aws.amazon.com/AWSJavaScriptSDK/latest/AWS/S3.html#putObject-property,
but with a few additional parameters, as follows.

#### KmsParams
A JSON document matching the params here: http://docs.aws.amazon.com/AWSJavaScriptSDK/latest/AWS/KMS.html#generateDataKey-property
At the very least, KmaParams.KeyId must be defined in order for encryption to happen. Note that, per AWS documentation,
either NumberOfBytes or KeySpec is required in addition to KeyId. Also note that if an EncryptionContext is given,
it must also be specified in the call to getObject.

#### CipherAlgorithm
The cipher algorithm to use when encrypting the object. Find the list by looking at crypto.getCiphers(). Optional,
will be ignored if KmsKeyId is missing.

#### DecryptedEncoding
The character encoding of the file to be uploaded to S3, to be used when encrypting (and thus decrypting) the
object. Optional, will be ignored if KmsKeyId is missing.


### cacheFor
Optionally call this method with a value > 0 in order to persist the object in an in-memory cache. This can be used
to avoid repetitively loading objects from S3 and decrypting via KMS in functions that are frequently executed. The
argument is the number of milliseconds for which the S3 object should remain in the cache before becoming stale. Keep
in mind that this limit will only be met as long as the function remains in memory in Lambda (i.e. does not follow
a cold-start of the function). Obviously, using a cache introduces the risk of the in-memory version getting out of
sync with the object in S3; be sure to balance performance against a reasonable TTL that will allow the function to
absorb edits to the object in a timely manner.


## Methodology
You can read about KMS envelope encryption above, but here's the summary:

To encrypt:
  1. Create a KMS key (it is assumed that you have already done this)
  2. Use the key from #1 to generate a KMS Data Key
  3. Use the KMS Data Key's Plaintext to encrypt your file
  4. Put the file into S3 with the KMS Data Key's CiphertextBlob in the object's Metadata
  5. Also include the cipher algorithm and decrypted encoding in the object's Metadata

To decrypt:
  1. Get the object
  2. Get the CiphertextBlob from the object's Metadata
  3. Decrypt the CiphertextBlob using the KMS library (don't need the original KMS KeyId)
  4. Use the decrypted key plus the cipher algorithm and decrypted encoding (from the Metadata)
     to decrypt the object content

Since you sometimes need to manually upload encrypted objects to S3 manually (i.e. not using this library), there
is a bash script included in the /bin folder that performs the "To encrypt" steps above:
[s3-put-encrypted](bin/s3-put-encrypted).


## Design Decisions

### Callbacks
I decided to keep the callback structure in line with the AWS SDK, to most closely match that API - even though I
prefer Promises. If you'd like to use this library as Promises, it's up to you promisify it (as would would the
AWS SDK).

### No Salt
I may be wrong, but it seems like the Java SDK for the S3 Encryption Client doesn't use a salt. This library matches
that decision, mostly because the crypto Cipher/Decipher classes don't support a salt. It might be possible to support
a salt using a different part of the crypto library, but it would require a major reworking of the flow because the KMS
Data Key is base64 but openssl functions that use a salt require hex.


## License
Copyright 2016 Gilt Groupe, Inc.

Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0