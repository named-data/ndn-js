/**
 * Copyright (C) 2014-2015 Regents of the University of California.
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
var KeyClass = require('../security-types').KeyClass;
var KeyType = require('../security-types').KeyType;
var SecurityException = require('../security-exception').SecurityException;
var PublicKey = require('../certificate/public-key').PublicKey;
var PrivateKeyStorage = require('./private-key-storage').PrivateKeyStorage;
var Blob = require('../../util/blob').Blob;
var util = require("util");
var crypto = require('crypto');
var fs = require('fs');
var path = require('path');

/**
 * Path to TPM folder
 */
var tpmPath = null;

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
	tpmPath = nonDefaultTpmPath || path.join(getUserHomePath(), '.ndn', 'ndnsec-tpm-file');
};
util.inherits(FilePrivateKeyStorage, PrivateKeyStorage);
exports.FilePrivateKeyStorage = FilePrivateKeyStorage;

/**
 * Check if a particular key exists.
 * @param {Name} keyName The name of the key.
 * @param {number} keyClass The class of the key, e.g. KeyClass.PUBLIC,
 * KeyClass.PRIVATE, or KeyClass.SYMMETRIC.
 * @returns {boolean} True if the key exists, otherwise false.
 */
FilePrivateKeyStorage.prototype.doesKeyExist = function (keyName, keyClass)
{
	return fs.existsSync(transformName(keyName, keyClass));
};

/**
 * Generate a pair of asymmetric keys; only currently supports RSA
 * @param {Name} keyName The name of the key pair.
 * @param {KeyType} keyType (optional) The type of the key pair, e.g. KeyType.RSA.
 * If omitted, use KeyType.RSA.
 * @param {number} keySize (optional) The size of the key pair. If omitted, use
 * 2048.
 */
FilePrivateKeyStorage.prototype.generateKeyPair = function (keyName, keyType, keySize)
{
	if (this.doesKeyExist(keyName, KeyClass.PUBLIC)) {
		throw new SecurityException("Public key already exists");
	}
	if (this.doesKeyExist(keyName, KeyClass.PRIVATE)) {
		throw new SecurityException("Public key already exists");
	}

	// build keys
	if (keyType === KeyType.RSA) {
		throw new Error("FilePrivateKeyStorage.deleteKeyPair is not implemented");
	}
	else {
		throw new SecurityException("Only RSA key generation currently supported");
	}
};

/**
 * Generate a symmetric key.
 * @param {Name} keyName The name of the key.
 * @param {KeyType} keyType (optional) The type of the key from KeyType, e.g.
 * KeyType.AES. If omitted, use KeyType.AES.
 * @param {number} keySize (optional) The size of the key. If omitted, use 256.
 */
FilePrivateKeyStorage.prototype.generateKey = function (keyName, keyType, keySize)
{
	throw new Error("FilePrivateKeyStorage.generateKey is not implemented");
};

/**
 * Delete a pair of asymmetric keys. If the key doesn't exist, do nothing.
 * @param {Name} keyName The name of the key pair.
 */
FilePrivateKeyStorage.prototype.deleteKeyPair = function (keyName)
{
	this.deleteKey(keyName);
};

/**
 * Delete all keys with this name. If the key doesn't exist, do nothing.
 * @param {Name} keyName The name of the key pair.
 */
FilePrivateKeyStorage.prototype.deleteKey = function (keyName)
{
	for (var keyClass in KeyClass) {
		if (this.doesKeyExist(keyName, keyClass)) {
			var filePath = transformName(keyName, keyClass);
			fs.unlinkSync(filePath);
		}
	}
};

/**
 * Get the public key
 * @param {Name} keyName The name of public key.
 * @returns {PublicKey} The public key.
 */
FilePrivateKeyStorage.prototype.getPublicKey = function (keyName)
{
	var buffer = read(keyName, KeyClass.PUBLIC);
	return new PublicKey(new Blob(buffer));
};

///**
// * Get the public key
// * @param {Name} keyName The name of public key.
// * @returns {PublicKey} The public key.
// */
//FilePrivateKeyStorage.prototype.getPrivateKey = function (keyName)
//{
//	var buffer = read(keyName, KeyClass.PRIVATE);
//	return new PublicKey(new Blob(buffer));
//};
//
///**
// * Get the symmetric key
// * 
// * @param {Name} keyName The name of symmetric key.
// * @returns {PublicKey} The symmetric key.
// */
//FilePrivateKeyStorage.prototype.getSymmetricKey = function (keyName)
//{
//	var buffer = read(keyName, KeyClass.SYMMETRIC);
//	return new PublicKey(new Blob(buffer));
//};

/**
 * Fetch the private key for keyName and sign the data, returning a signature Blob.
 * @param {Buffer} data Pointer to the input byte array.
 * @param {Name} keyName The name of the signing key.
 * @param {number} digestAlgorithm (optional) The digest algorithm from
 * DigestAlgorithm, such as DigestAlgorithm.SHA256. If omitted, use
 * DigestAlgorithm.SHA256.
 * @returns {Blob} The signature, or a isNull() Blob if signing fails.
 */
FilePrivateKeyStorage.prototype.sign = function (data, keyName, digestAlgorithm)
{
	throw new Error("FilePrivateKeyStorage.sign is not implemented");
};

/**
 * Decrypt data.
 * @param {Name} keyName The name of the decrypting key.
 * @param {Buffer} data The byte to be decrypted.
 * @param {boolean} isSymmetric (optional) If true symmetric encryption is used,
 * otherwise asymmetric encryption is used. If omitted, use asymmetric
 * encryption.
 * @returns {Blob} The decrypted data.
 */
FilePrivateKeyStorage.prototype.decrypt = function (keyName, data, isSymmetric)
{
	throw new Error("FilePrivateKeyStorage.decrypt is not implemented");
};

/**
 * Encrypt data.
 * @param {Name} keyName The name of the encrypting key.
 * @param {Buffer} data The byte to be encrypted.
 * @param {boolean} isSymmetric (optional) If true symmetric encryption is used,
 * otherwise asymmetric encryption is used. If omitted, use asymmetric
 * encryption.
 * @returns {Blob} The encrypted data.
 */
FilePrivateKeyStorage.prototype.encrypt = function (keyName, data, isSymmetric)
{
	throw new Error("FilePrivateKeyStorage.encrypt is not implemented");
};

/** PRIVATE METHODS **/

/**
 * File extensions by KeyClass type
 */
var KeyClassExtensions = {};
KeyClassExtensions[KeyClass.PUBLIC] = '.pub';
KeyClassExtensions[KeyClass.PRIVATE] = '.pri';
KeyClassExtensions[KeyClass.SYMMETRIC] = '.key';

/**
 * Write to a key file
 * @param {Name} keyName
 * @param {KeyClass} keyClass [PUBLIC, PRIVATE, SYMMETRIC]
 * @param {Buffer} bytes
 * @throws Error if the file cannot be written to
 */
function write(keyName, keyClass, bytes) {
	var options = { mode: parseInt('0400') };
	if(keyClass === KeyClass.PUBLIC) options.mode = parseInt('0444');
	fs.writeFileSync(transformName(keyName, keyClass), bytes.toString('base64'), options);
}

/**
 * Read from a key file
 * @param keyName
 * @param keyClass [PUBLIC, PRIVATE, SYMMETRIC]
 * @return {Buffer} key bytes
 * @throws Error if the file cannot be read from
 */
function read(keyName, keyClass){
	var base64 = fs.readFileSync(transformName(keyName, keyClass)).toString();
	return new Buffer(base64, 'base64');
}

/**
 * Retrieve the user's current home directory
 * @returns {string} path to the user's home directory
 */
function getUserHomePath() {
	return process.env.HOME || process.env.HOMEPATH || process.env.USERPROFILE;
}

/**
 * Transform the key name into a file name
 * @param {Name} keyName
 * @param {KeyClass} keyClass
 */
function transformName(keyName, keyClass) {
	var hash = crypto.createHash('sha256');
	if (!hash) {
		throw new SecurityException('Could not instantiate SHA256 hash algorith.');
	}

	// hash the key name
	hash.update(new Buffer(keyName.toUri()));
	var fileName = hash.digest('base64');
	if (!fileName) {
		throw new SecurityException('Failed to hash file name: ' + keyName.toUri());
	}

	// return
	return path.join(tpmPath, fileName.replace(/\//g, '%') + KeyClassExtensions[keyClass]);
}