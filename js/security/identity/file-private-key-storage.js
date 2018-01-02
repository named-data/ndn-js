/**
 * Copyright (C) 2014-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: Andrew Brown <andrew.brown@intel.com>
 * From ndn-cxx security by Yingdi Yu <yingdi@cs.ucla.edu>.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU Lesser General Public License is in the file COPYING.
 */

/** @ignore */
var KeyClass = require('../security-types').KeyClass; /** @ignore */
var KeyType = require('../security-types').KeyType; /** @ignore */
var DigestAlgorithm = require('../security-types').DigestAlgorithm; /** @ignore */
var SecurityException = require('../security-exception.js').SecurityException; /** @ignore */
var PublicKey = require('../certificate/public-key.js').PublicKey; /** @ignore */
var PrivateKeyStorage = require('./private-key-storage.js').PrivateKeyStorage; /** @ignore */
var Blob = require('../../util/blob.js').Blob; /** @ignore */
var OID = require('../../encoding/oid.js').OID; /** @ignore */
var DerNode = require('../../encoding/der/der-node.js').DerNode; /** @ignore */
var DataUtils = require('../../encoding/data-utils.js').DataUtils; /** @ignore */
var SyncPromise = require('../../util/sync-promise.js').SyncPromise; /** @ignore */
var util = require('util');
// Use capitalized Crypto to not clash with the browser's crypto.subtle.
/** @ignore */
var Crypto = require('../../crypto.js'); /** @ignore */
var fs = require('fs'); /** @ignore */
var path = require('path'); /** @ignore */
var rsaKeygen = null;
try {
  // This should be installed with: sudo npm install rsa-keygen
  rsaKeygen = require('rsa-keygen');
}
catch (e) {}

/**
 * FilePrivateKeyStorage works with NFD's default private key storage, the files
 * stored in .ndn/ndnsec-tpm-file. This library will not be available from the
 * browser
 * @param {string} nonDefaultTpmPath if desired, override the default TPM path (i.e. .ndn/ndnsec-tpm-file)
 * @constructor
 */
var FilePrivateKeyStorage = function FilePrivateKeyStorage(nonDefaultTpmPath)
{
  PrivateKeyStorage.call(this);
  // Path to TPM folder.
  this.tpmPath = nonDefaultTpmPath ||
    path.join(FilePrivateKeyStorage.getUserHomePath(), '.ndn', 'ndnsec-tpm-file');
};
util.inherits(FilePrivateKeyStorage, PrivateKeyStorage);
exports.FilePrivateKeyStorage = FilePrivateKeyStorage;

/**
 * Check if a particular key exists.
 * @param {Name} keyName The name of the key.
 * @param {number} keyClass The class of the key, e.g. KeyClass.PUBLIC,
 * KeyClass.PRIVATE, or KeyClass.SYMMETRIC.
 * @return {SyncPromise} A promise which returns true if the key exists.
 */
FilePrivateKeyStorage.prototype.doesKeyExistPromise = function(keyName, keyClass)
{
  var exists = fs.existsSync
    (this.nameTransform(keyName.toUri(), KeyClassExtensions[keyClass]));
  return SyncPromise.resolve(exists);
};

/**
 * Generate a pair of asymmetric keys; only currently supports RSA
 * @param {Name} keyName The name of the key pair.
 * @param {KeyParams} params The parameters of the key.
 * @return {SyncPromise} A promise that fulfills when the pair is generated.
 */
FilePrivateKeyStorage.prototype.generateKeyPairPromise = function
  (keyName, params)
{
  if (this.doesKeyExist(keyName, KeyClass.PUBLIC)) {
    return SyncPromise.reject(new SecurityException(new Error
      ("Public key already exists")));
  }
  if (this.doesKeyExist(keyName, KeyClass.PRIVATE)) {
    return SyncPromise.reject(new SecurityException(new Error
      ("Private key already exists")));
  }

  // build keys
  if (params.getKeyType() === KeyType.RSA) {
    if (!rsaKeygen)
      return SyncPromise.reject(new SecurityException(new Error
        ("Need to install rsa-keygen: sudo npm install rsa-keygen")));

    var keyPair = rsaKeygen.generate(params.getKeySize());

    // Get the public key DER from the PEM string.
    var publicKeyBase64 = keyPair.public_key.toString().replace
      ("-----BEGIN PUBLIC KEY-----", "").replace
      ("-----END PUBLIC KEY-----", "");
    var publicKey = new Buffer(publicKeyBase64, 'base64');

    // Get the PKCS1 private key DER from the PEM string and encode as PKCS8.
    var privateKeyBase64 = keyPair.private_key.toString().replace
      ("-----BEGIN RSA PRIVATE KEY-----", "").replace
      ("-----END RSA PRIVATE KEY-----", "");
    var pkcs1PrivateKeyDer = new Buffer(privateKeyBase64, 'base64');
    var privateKey = PrivateKeyStorage.encodePkcs8PrivateKey
      (pkcs1PrivateKeyDer, new OID(PrivateKeyStorage.RSA_ENCRYPTION_OID),
       new DerNode.DerNull()).buf();

    // save
    this.write(keyName, KeyClass.PRIVATE, privateKey);
    this.write(keyName, KeyClass.PUBLIC, publicKey);
  }
  else {
    return SyncPromise.reject(new SecurityException(new Error
      ("Only RSA key generation currently supported")));
  }

  return SyncPromise.resolve();
};

/**
 * Delete a pair of asymmetric keys. If the key doesn't exist, do nothing.
 * @param {Name} keyName The name of the key pair.
 * @return {SyncPromise} A promise that fulfills when the key pair is deleted.
 */
FilePrivateKeyStorage.prototype.deleteKeyPairPromise = function (keyName)
{
  this.deleteKey(keyName);
  return SyncPromise.resolve();
};

/**
 * Delete all keys with this name. If the key doesn't exist, do nothing.
 * @param {Name} keyName The name of the key pair.
 */
FilePrivateKeyStorage.prototype.deleteKey = function (keyName)
{
  for (var keyClassName in KeyClass) {
    var keyClass = KeyClass[keyClassName];
    if (this.doesKeyExist(keyName, keyClass)) {
      var filePath = this.nameTransform(keyName.toUri(), KeyClassExtensions[keyClass]);
      fs.unlinkSync(filePath);
    }
  }
};

/**
 * Get the public key
 * @param {Name} keyName The name of public key.
 * @return {SyncPromise} A promise that returns the PublicKey.
 */
FilePrivateKeyStorage.prototype.getPublicKeyPromise = function (keyName)
{
  var buffer = this.read(keyName, KeyClass.PUBLIC);
  return SyncPromise.resolve(new PublicKey(new Blob(buffer)));
};

/**
 * Fetch the private key for keyName and sign the data to produce a signature Blob.
 * @param {Buffer} data Pointer to the input byte array.
 * @param {Name} keyName The name of the signing key.
 * @param {number} digestAlgorithm (optional) The digest algorithm from
 * DigestAlgorithm, such as DigestAlgorithm.SHA256. If omitted, use
 * DigestAlgorithm.SHA256.
 * @return {SyncPromise} A promise that returns the signature Blob.
 */
FilePrivateKeyStorage.prototype.signPromise = function
  (data, keyName, digestAlgorithm)
{
  if (digestAlgorithm == null)
    digestAlgorithm = DigestAlgorithm.SHA256;

  if (!this.doesKeyExist(keyName, KeyClass.PRIVATE))
    return SyncPromise.reject(new SecurityException(new Error
      ("FilePrivateKeyStorage.sign: private key doesn't exist")));

  if (digestAlgorithm != DigestAlgorithm.SHA256)
    return SyncPromise.reject(new SecurityException(new Error
      ("FilePrivateKeyStorage.sign: Unsupported digest algorithm")));

  // Retrieve the private key.
  var keyType = [-1];
  var privateKey = this.getPrivateKey(keyName, keyType);

  // Sign.
  if (keyType[0] == KeyType.RSA) {
    var rsa = Crypto.createSign('RSA-SHA256');
    rsa.update(data);

    var signature = new Buffer(DataUtils.toNumbersIfString(rsa.sign(privateKey)));
    return SyncPromise.resolve(new Blob(signature, false));
  }
  else
    // We don't expect this to happen since getPrivateKey checked it.
    return SyncPromise.reject(new SecurityException(new Error
      ("FilePrivateKeyStorage: Unsupported signature key type " + keyType[0])));
};

/** PRIVATE METHODS **/

/**
 * A private method to get the private key.
 * @param {Name} keyName The name of private key.
 * @param {Array<KeyType>} keyType Set keyType[0] to the KeyType.
 * @return {string} The PEM-encoded private key for use by the crypto module.
 */
FilePrivateKeyStorage.prototype.getPrivateKey = function(keyName, keyType)
{
  var pkcs8Der = this.read(keyName, KeyClass.PRIVATE);

  // The private key is generated by NFD which stores as PKCS #8. Decode it
  // to find the algorithm OID and the inner private key DER.
  var parsedNode = DerNode.parse(pkcs8Der);
  var pkcs8Children = parsedNode.getChildren();
  // Get the algorithm OID and parameters.
  var algorithmIdChildren = DerNode.getSequence(pkcs8Children, 1).getChildren();
  var oidString = algorithmIdChildren[0].toVal();
  var algorithmParameters = algorithmIdChildren[1];
  // Get the value of the 3rd child which is the octet string.
  var privateKeyDer = pkcs8Children[2].toVal();

  if (oidString == PrivateKeyStorage.RSA_ENCRYPTION_OID) {
    keyType[0] = KeyType.RSA;

    // Encode the DER as PEM.
    var keyBase64 = privateKeyDer.buf().toString('base64');
    var keyPem = "-----BEGIN RSA PRIVATE KEY-----\n";
    for (var i = 0; i < keyBase64.length; i += 64)
      keyPem += (keyBase64.substr(i, 64) + "\n");
    keyPem += "-----END RSA PRIVATE KEY-----";

    return keyPem;
  }
  else
    throw new SecurityException(new Error
      ("FilePrivateKeyStorage.sign: Unrecognized private key OID: " + oidString));
};

/**
 * File extensions by KeyClass type
 */
var KeyClassExtensions = {};
KeyClassExtensions[KeyClass.PUBLIC] = '.pub';
KeyClassExtensions[KeyClass.PRIVATE] = '.pri';
KeyClassExtensions[KeyClass.SYMMETRIC] = '.key';

/**
 * Write to a key file. If keyClass is PRIVATE, then also update mapping.txt.
 * @param {Name} keyName
 * @param {KeyClass} keyClass [PUBLIC, PRIVATE, SYMMETRIC]
 * @param {Buffer} bytes
 * @throws Error if the file cannot be written to
 */
FilePrivateKeyStorage.prototype.write = function(keyName, keyClass, bytes) {
  var options = { mode: parseInt('0400', 8) };
  if(keyClass === KeyClass.PUBLIC) options.mode = parseInt('0444', 8);

  var filePath;
  if (keyClass == KeyClass.PRIVATE)
    filePath = this.maintainMapping(keyName.toUri()) + ".pri";
  else
    filePath = this.nameTransform(keyName.toUri(), KeyClassExtensions[keyClass]);
  fs.writeFileSync(filePath, bytes.toString('base64'), options);
};

/**
 * Read from a key file
 * @param {Name} keyName
 * @param {number} keyClass An int from KeyClass.
 * @return {Buffer} key bytes
 * @throws Error if the file cannot be read from
 */
FilePrivateKeyStorage.prototype.read = function(keyName, keyClass){
  var base64 = fs.readFileSync
    (this.nameTransform(keyName.toUri(), KeyClassExtensions[keyClass])).toString();
  return new Buffer(base64, 'base64');
};

/**
 * Retrieve the user's current home directory
 * @return {string} path to the user's home directory
 */
FilePrivateKeyStorage.getUserHomePath = function() {
  return process.env.HOME || process.env.HOMEPATH || process.env.USERPROFILE;
};

/**
 * Transform a key name to its hashed file path.
 * @param {string} keyNameUri The key name URI which is transformed to a file path.
 * @param {string} extension The file name extension. You can use
 * KeyClassExtensions[keyClass].
 * @return {string} The hashed key file path.
 */
FilePrivateKeyStorage.prototype.nameTransform = function(keyNameUri, extension)
{
  var hash = Crypto.createHash('sha256');
  if (!hash) {
    throw new SecurityException(new Error('Could not instantiate SHA256 hash algorith.'));
  }

  // hash the key name
  hash.update(new Buffer(keyNameUri));
  var fileName = hash.digest('base64');
  if (!fileName) {
    throw new SecurityException(new Error('Failed to hash file name: ' + keyNameUri));
  }

  // return
  return path.join(this.tpmPath, fileName.replace(/\//g, '%') + extension);
};

/**
 * Use nameTransform to get the file path for keyName (without the extension)
 * and also add to the mapping.txt file.
 * @param {string} keyNameUri The key name URI which is transformed to a file path.
 * @return {string} The key file path without the extension.
 */
FilePrivateKeyStorage.prototype.maintainMapping = function(keyNameUri)
{
  var keyFilePathNoExtension = this.nameTransform(keyNameUri, "");

  var mappingFilePath = path.join(this.tpmPath, "mapping.txt");
  fs.appendFileSync
    (mappingFilePath, keyNameUri + ' ' + keyFilePathNoExtension + '\n');

  return keyFilePathNoExtension;
};
