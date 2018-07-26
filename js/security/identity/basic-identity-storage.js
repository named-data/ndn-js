/**
 * Copyright (C) 2015-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
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
var Name = require('../../name.js').Name; /** @ignore */
var Blob = require('../../util/blob.js').Blob; /** @ignore */
var Sqlite3Promise = require('../../util/sqlite3-promise.js').Sqlite3Promise; /** @ignore */
var KeyLocator = require('../../key-locator.js').KeyLocator; /** @ignore */
var SecurityException = require('../security-exception.js').SecurityException; /** @ignore */
var IdentityCertificate = require('../certificate/identity-certificate.js').IdentityCertificate; /** @ignore */
var IdentityStorage = require('./identity-storage.js').IdentityStorage; /** @ignore */
var path = require('path');

/**
 * BasicIdentityStorage extends IdentityStorage to implement basic storage of
 * identity, public keys and certificates using the Node.js sqlite3 module.
 * Create a new BasicIdentityStorage to use the SQLite3 file in the default
 * location, or the optional given file.
 * @param {string} databaseFilePath (optional) The path of the SQLite3 file. If
 * omitted, use the default file (~/.ndn/ndnsec-public-info.db).
 * @param {function} initialCheckPromise (optional) If supplied, then after
 * initializing the database this calls initialCheckPromise() which returns a
 * Promise that resolves when the initial check passes or is rejected for a
 * problem.
 * @constructor
 */
var BasicIdentityStorage = function BasicIdentityStorage
  (databaseFilePath, initialCheckPromise)
{
  // Call the base constructor.
  IdentityStorage.call(this);

  // Temporarlity reassign to resolve the different overloaded forms.
  var arg1 = databaseFilePath;
  var arg2 = initialCheckPromise;
  // arg1,     arg2 may be:
  // string,   function
  // string,   null
  // function, null
  // null,     null
  if (typeof arg1 === "string")
    databaseFilePath = arg1;
  else
    databaseFilePath = null;

  if (typeof arg1 === "function")
    initialCheckPromise = arg1;
  else if (typeof arg2 === "function")
    initialCheckPromise = arg2;
  else
    initialCheckPromise = null;

  if (databaseFilePath == undefined || databaseFilePath == "")
    databaseFilePath = BasicIdentityStorage.getDefaultDatabaseFilePath();

  var initializeDatabasePromise;
  if (initialCheckPromise) {
    // Call our initializeDatabasePromise_ and then initialCheckPromise.
    initializeDatabasePromise = function(database) {
      return BasicIdentityStorage.initializeDatabasePromise_(database)
      .then(function() { return initialCheckPromise(); });
    };
  }
  else
    initializeDatabasePromise = BasicIdentityStorage.initializeDatabasePromise_;

  this.database_ = new Sqlite3Promise
    (databaseFilePath, initializeDatabasePromise);
};

BasicIdentityStorage.prototype = new IdentityStorage();
BasicIdentityStorage.prototype.name = "BasicIdentityStorage";

exports.BasicIdentityStorage = BasicIdentityStorage;

/**
 * Check if the specified identity already exists.
 * @param {Name} identityName The identity name.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which returns true if the identity exists.
 */
BasicIdentityStorage.prototype.doesIdentityExistPromise = function
  (identityName, useSync)
{
  if (useSync)
    return Promise.reject(new SecurityException(new Error
      ("BasicIdentityStorage.doesIdentityExistPromise is only supported for async")));

  return this.getPromise_
    ("SELECT count(*) FROM Identity WHERE identity_name=?", identityName.toUri())
  .then(function(row) {
    if (row["count(*)"] > 0)
      return Promise.resolve(true);
    else
      return Promise.resolve(false);
  });
};

/**
 * Add a new identity. Do nothing if the identity already exists.
 * @param {Name} identityName The identity name to be added.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which fulfills when the identity is added.
 */
BasicIdentityStorage.prototype.addIdentityPromise = function(identityName, useSync)
{
  if (useSync)
    return Promise.reject(new SecurityException(new Error
      ("BasicIdentityStorage.addIdentityPromise is only supported for async")));

  var thisStorage = this;
  var identityUri = identityName.toUri();
  return this.doesIdentityExistPromise(identityName)
  .then(function(exists) {
    if (exists)
      return Promise.resolve();

    return thisStorage.runPromise_
      ("INSERT INTO Identity (identity_name) VALUES(?)", identityUri);
  });
};

/**
 * Check if the specified key already exists.
 * @param {Name} keyName The name of the key.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which returns true if the key exists.
 */
BasicIdentityStorage.prototype.doesKeyExistPromise = function(keyName, useSync)
{
  if (useSync)
    return Promise.reject(new SecurityException(new Error
      ("BasicIdentityStorage.doesKeyExistPromise is only supported for async")));

  var keyId = keyName.get(-1).toEscapedString();
  var identityName = keyName.getPrefix(-1);

  return this.getPromise_
    ("SELECT count(*) FROM Key WHERE identity_name=? AND key_identifier=?",
     [identityName.toUri(), keyId])
  .then(function(row) {
    if (row["count(*)"] > 0)
      return Promise.resolve(true);
    else
      return Promise.resolve(false);
  });
};

/**
 * Add a public key to the identity storage. Also call addIdentity to ensure
 * that the identityName for the key exists. However, if the key already
   * exists, do nothing.
 * @param {Name} keyName The name of the public key to be added.
 * @param {number} keyType Type of the public key to be added from KeyType, such
 * as KeyType.RSA..
 * @param {Blob} publicKeyDer A blob of the public key DER to be added.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which fulfills when complete.
 */
BasicIdentityStorage.prototype.addKeyPromise = function
  (keyName, keyType, publicKeyDer, useSync)
{
  if (useSync)
    return Promise.reject(new SecurityException(new Error
      ("BasicIdentityStorage.addKeyPromise is only supported for async")));

  if (keyName.size() === 0)
    return Promise.resolve();

  var thisStorage = this;
  return this.doesKeyExistPromise(keyName)
  .then(function(exists) {
    if (exists)
      return Promise.resolve();

    var identityName = keyName.getPrefix(-1);
    var identityUri = identityName.toUri();

    return thisStorage.addIdentityPromise(identityName)
    .then(function() {
      var keyId = keyName.get(-1).toEscapedString();
      var keyBuffer = publicKeyDer.buf();

      return thisStorage.runPromise_
        ("INSERT INTO Key (identity_name, key_identifier, key_type, public_key) VALUES(?,?,?,?)",
         [identityUri, keyId, keyType, keyBuffer]);
    });
  });
};

/**
 * Get the public key DER blob from the identity storage.
 * @param {Name} keyName The name of the requested public key.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which returns the DER Blob, or a promise rejected
 * with SecurityException if the key doesn't exist.
 */
BasicIdentityStorage.prototype.getKeyPromise = function(keyName, useSync)
{
  if (useSync)
    return Promise.reject(new SecurityException(new Error
      ("BasicIdentityStorage.getKeyPromise is only supported for async")));

  if (keyName.size() === 0)
    return Promise.reject(new SecurityException(new Error
      ("BasicIdentityStorage.getKeyPromise: Empty keyName")));

  var identityUri = keyName.getPrefix(-1).toUri();
  var keyId = keyName.get(-1).toEscapedString();

  return this.getPromise_
    ("SELECT public_key FROM Key WHERE identity_name=? AND key_identifier=?",
     [identityUri, keyId])
  .then(function(row) {
    if (row)
      return Promise.resolve(new Blob(row.public_key, false));
    else
      return Promise.reject(new SecurityException(new Error
        ("BasicIdentityStorage.getKeyPromise: The key does not exist")));
  });
};

/**
 * Check if the specified certificate already exists.
 * @param {Name} certificateName The name of the certificate.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which returns true if the certificate exists.
 */
BasicIdentityStorage.prototype.doesCertificateExistPromise = function
  (certificateName, useSync)
{
  if (useSync)
    return Promise.reject(new SecurityException(new Error
      ("BasicIdentityStorage.doesCertificateExistPromise is only supported for async")));

  return this.getPromise_
    ("SELECT count(*) FROM Certificate WHERE cert_name=?", certificateName.toUri())
  .then(function(row) {
    if (row["count(*)"] > 0)
      return Promise.resolve(true);
    else
      return Promise.resolve(false);
  });
};

/**
 * Add a certificate to the identity storage. Also call addKey to ensure that
 * the certificate key exists. If the certificate is already installed, don't
 * replace it.
 * @param {IdentityCertificate} certificate The certificate to be added.  This
 * makes a copy of the certificate.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which fulfills when finished.
 */
BasicIdentityStorage.prototype.addCertificatePromise = function
  (certificate, useSync)
{
  if (useSync)
    return Promise.reject(new SecurityException(new Error
      ("BasicIdentityStorage.addCertificatePromise is only supported for async")));

  var certificateName = certificate.getName();
  var keyName = certificate.getPublicKeyName();

  var thisStorage = this;
  return this.addKeyPromise
    (keyName, certificate.getPublicKeyInfo().getKeyType(),
     certificate.getPublicKeyInfo().getKeyDer(), useSync)
  .then(function() {
    return thisStorage.doesCertificateExistPromise(certificateName);
  })
  .then(function(exists) {
    if (exists)
      return Promise.resolve();

    var keyId = keyName.get(-1).toEscapedString();
    var identity = keyName.getPrefix(-1);

    // Insert the certificate.

    var signature = certificate.getSignature();
    var signerName = KeyLocator.getFromSignature(signature).getKeyName();
    // Convert from milliseconds to seconds since 1/1/1970.
    var notBefore = Math.floor(certificate.getNotBefore() / 1000.0);
    var notAfter = Math.floor(certificate.getNotAfter() / 1000.0);
    var encodedCert = certificate.wireEncode().buf();

    return thisStorage.runPromise_
      ("INSERT INTO Certificate (cert_name, cert_issuer, identity_name, key_identifier, not_before, not_after, certificate_data) " +
       "VALUES (?,?,?,?,?,?,?)",
       [certificateName.toUri(), signerName.toUri(), identity.toUri(), keyId,
        notBefore, notAfter, encodedCert]);
  });
};

/**
 * Get a certificate from the identity storage.
 * @param {Name} certificateName The name of the requested certificate.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which returns the requested
 * IdentityCertificate, or a promise rejected with SecurityException if the
 * certificate doesn't exist.
 */
BasicIdentityStorage.prototype.getCertificatePromise = function
  (certificateName, useSync)
{
  if (useSync)
    return Promise.reject(new SecurityException(new Error
      ("BasicIdentityStorage.getCertificatePromise is only supported for async")));

  return this.getPromise_
    ("SELECT certificate_data FROM Certificate WHERE cert_name=?",
     certificateName.toUri())
  .then(function(row) {
    if (row) {
      var certificate = new IdentityCertificate()
      try {
        certificate.wireDecode(new Blob(row.certificate_data, false))
      } catch (ex) {
        return Promise.reject(new SecurityException(new Error
          ("BasicIdentityStorage.getCertificatePromise: The certificate cannot be decoded")));
      }
      return Promise.resolve(certificate);
    }
    else
      return Promise.reject(new SecurityException(new Error
        ("BasicIdentityStorage.getCertificatePromise: The certificate does not exist")));
  });
};

/**
 * Get the TPM locator associated with this storage.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which returns the TPM locator, or a promise
 * rejected with SecurityException if the TPM locator doesn't exist.
 */
BasicIdentityStorage.prototype.getTpmLocatorPromise = function(useSync)
{
  if (useSync)
    return Promise.reject(new SecurityException(new Error
      ("BasicIdentityStorage.getTpmLocatorPromise is only supported for async")));

  return this.getPromise_("SELECT tpm_locator FROM TpmInfo")
  .then(function(row) {
    if (row)
      return Promise.resolve(row.tpm_locator);
    else
      return Promise.reject(new SecurityException(new Error
        ("BasicIdentityStorage.getTpmLocatorPromise: The TPM info does not exist.")));
  });
};

/*****************************************
 *           Get/Set Default             *
 *****************************************/

/**
 * Get the default identity.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which returns the Name of default identity, or a
 * promise rejected with SecurityException if the default identity is not set.
 */
BasicIdentityStorage.prototype.getDefaultIdentityPromise = function(useSync)
{
  if (useSync)
    return Promise.reject(new SecurityException(new Error
      ("BasicIdentityStorage.getDefaultIdentityPromise is only supported for async")));

  return this.getPromise_
    ("SELECT identity_name FROM Identity WHERE default_identity=1")
  .then(function(row) {
    if (row)
      return Promise.resolve(new Name(row.identity_name));
    else
      return Promise.reject(new SecurityException(new Error
        ("BasicIdentityStorage.getDefaultIdentityPromise: The default identity is not defined")));
  });
};

/**
 * Get the default key name for the specified identity.
 * @param {Name} identityName The identity name.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which returns the default key Name, or a promise
 * rejected with SecurityException if the default key name for the identity is
 * not set.
 */
BasicIdentityStorage.prototype.getDefaultKeyNameForIdentityPromise = function
  (identityName, useSync)
{
  if (useSync)
    return Promise.reject(new SecurityException(new Error
      ("BasicIdentityStorage.getDefaultKeyNameForIdentityPromise is only supported for async")));

  return this.getPromise_
    ("SELECT key_identifier FROM Key WHERE identity_name=? AND default_key=1",
     identityName.toUri())
  .then(function(row) {
    if (row)
      return Promise.resolve(new Name(identityName).append(row.key_identifier));
    else
      return Promise.reject(new SecurityException(new Error
        ("BasicIdentityStorage.getDefaultKeyNameForIdentityPromise: The default key for the identity is not defined")));
  });
};

/**
 * Get the default certificate name for the specified key.
 * @param {Name} keyName The key name.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which returns the default certificate Name, or a
 * promise rejected with SecurityException if the default certificate name for
 * the key name is not set.
 */
BasicIdentityStorage.prototype.getDefaultCertificateNameForKeyPromise = function
  (keyName, useSync)
{
  if (useSync)
    return Promise.reject(new SecurityException(new Error
      ("BasicIdentityStorage.getDefaultCertificateNameForKeyPromise is only supported for async")));

  var keyId = keyName.get(-1).toEscapedString();
  var identityName = keyName.getPrefix(-1);

  return this.getPromise_
    ("SELECT cert_name FROM Certificate WHERE identity_name=? AND key_identifier=? AND default_cert=1",
     [identityName.toUri(), keyId])
  .then(function(row) {
    if (row)
      return Promise.resolve(new Name(row.cert_name));
    else
      return Promise.reject(new SecurityException(new Error
        ("BasicIdentityStorage.getDefaultCertificateNameForKeyPromise: The default certificate for the key name is not defined")));
  });
};

/**
 * Append all the identity names to the nameList.
 * @param {Array<Name>} nameList Append result names to nameList.
 * @param {boolean} isDefault If true, add only the default identity name. If
 * false, add only the non-default identity names.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which fulfills when the names are added to
 * nameList.
 */
BasicIdentityStorage.prototype.getAllIdentitiesPromise = function
  (nameList, isDefault, useSync)
{
  if (useSync)
    return Promise.reject(new SecurityException(new Error
      ("BasicIdentityStorage.getAllIdentitiesPromise is only supported for async")));

  var query;
  if (isDefault)
    query = "SELECT identity_name FROM Identity WHERE default_identity=1";
  else
    query = "SELECT identity_name FROM Identity WHERE default_identity=0";

  return this.eachPromise_(query, [], function(err, row) {
    nameList.push(new Name(row.identity_name));
  });
};

/**
 * Append all the key names of a particular identity to the nameList.
 * @param {Name} identityName The identity name to search for.
 * @param {Array<Name>} nameList Append result names to nameList.
 * @param {boolean} isDefault If true, add only the default key name. If false,
 * add only the non-default key names.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which fulfills when the names are added to
 * nameList.
 */
BasicIdentityStorage.prototype.getAllKeyNamesOfIdentityPromise = function
  (identityName, nameList, isDefault, useSync)
{
  if (useSync)
    return Promise.reject(new SecurityException(new Error
      ("BasicIdentityStorage.getAllKeyNamesOfIdentityPromise is only supported for async")));

  var query;
  if (isDefault)
    query = "SELECT key_identifier FROM Key WHERE default_key=1 and identity_name=?";
  else
    query = "SELECT key_identifier FROM Key WHERE default_key=0 and identity_name=?";

  return this.eachPromise_(query, identityName.toUri(), function(err, row) {
    nameList.push(new Name(identityName).append(row.key_identifier));
  });
};

/**
 * Append all the certificate names of a particular key name to the nameList.
 * @param {Name} keyName The key name to search for.
 * @param {Array<Name>} nameList Append result names to nameList.
 * @param {boolean} isDefault If true, add only the default certificate name.
 * If false, add only the non-default certificate names.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which fulfills when the names are added to
 * nameList.
 */
BasicIdentityStorage.prototype.getAllCertificateNamesOfKeyPromise = function
  (keyName, nameList, isDefault, useSync)
{
  if (useSync)
    return Promise.reject(new SecurityException(new Error
      ("BasicIdentityStorage.getAllCertificateNamesOfKeyPromise is only supported for async")));

  var query;
  if (isDefault)
    query = "SELECT cert_name FROM Certificate" +
            "  WHERE default_cert=1 and identity_name=? and key_identifier=?";
  else
    query = "SELECT cert_name FROM Certificate" +
            "  WHERE default_cert=0 and identity_name=? and key_identifier=?";

  return this.eachPromise_
    (query, [keyName.getPrefix(-1).toUri(), keyName.get(-1).toEscapedString()],
     function(err, row) {
    nameList.push(new Name(row.cert_name));
  });
};

/**
 * Set the default identity.  If the identityName does not exist, then clear the
 * default identity so that getDefaultIdentity() throws an exception.
 * @param {Name} identityName The default identity name.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which fulfills when the default identity is set.
 */
BasicIdentityStorage.prototype.setDefaultIdentityPromise = function
  (identityName, useSync)
{
  if (useSync)
    return Promise.reject(new SecurityException(new Error
      ("BasicIdentityStorage.setDefaultIdentityPromise is only supported for async")));

  var thisStorage = this;

  // Reset the previous default identity.
  return this.runPromise_
    ("UPDATE Identity SET default_identity=0 WHERE default_identity=1")
  .then(function() {
    // Set the current default identity.
    return thisStorage.runPromise_
      ("UPDATE Identity SET default_identity=1 WHERE identity_name=?",
       identityName.toUri());
  });
};

/**
 * Set a key as the default key of an identity. The identity name is inferred
 * from keyName.
 * @param {Name} keyName The name of the key.
 * @param {Name} identityNameCheck (optional) The identity name to check that the
 * keyName contains the same identity name. If an empty name, it is ignored.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which fulfills when the default key name is set.
 */
BasicIdentityStorage.prototype.setDefaultKeyNameForIdentityPromise = function
  (keyName, identityNameCheck, useSync)
{
  useSync = (typeof identityNameCheck === "boolean") ? identityNameCheck : useSync;
  identityNameCheck = (identityNameCheck instanceof Name) ? identityNameCheck : null;

  if (useSync)
    return Promise.reject(new SecurityException(new Error
      ("BasicIdentityStorage.setDefaultKeyNameForIdentityPromise is only supported for async")));

  var keyId = keyName.get(-1).toEscapedString();
  var identityName = keyName.getPrefix(-1);

  if (identityNameCheck != null && identityNameCheck.size() != 0 &&
      !identityNameCheck.equals(identityName))
    return Promise.reject(new SecurityException(new Error
      ("Specified identity name does not match the key name")));

  var thisStorage = this;

  // Reset the previous default key.
  var identityUri = identityName.toUri();
  return this.runPromise_
    ("UPDATE Key SET default_key=0 WHERE default_key=1 and identity_name=?",
     identityUri)
  .then(function() {
    // Set the current default key.
    return thisStorage.runPromise_
      ("UPDATE Key SET default_key=1 WHERE identity_name=? AND key_identifier=?",
       [identityUri, keyId]);
  });
};

/**
 * Set the default key name for the specified identity.
 * @param {Name} keyName The key name.
 * @param {Name} certificateName The certificate name.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which fulfills when the default certificate name
 * is set.
 */
BasicIdentityStorage.prototype.setDefaultCertificateNameForKeyPromise = function
  (keyName, certificateName, useSync)
{
  if (useSync)
    return Promise.reject(new SecurityException(new Error
      ("BasicIdentityStorage.setDefaultCertificateNameForKeyPromise is only supported for async")));

  var keyId = keyName.get(-1).toEscapedString();
  var identityName = keyName.getPrefix(-1);
  var thisStorage = this;

  // Reset the previous default certificate.
  var identityUri = identityName.toUri();
  return this.runPromise_
    ("UPDATE Certificate SET default_cert=0 WHERE default_cert=1 AND identity_name=? AND key_identifier=?",
     [identityUri, keyId])
  .then(function() {
    // Set the current default certificate.
    return thisStorage.runPromise_
      ("UPDATE Certificate SET default_cert=1 WHERE identity_name=? AND key_identifier=? AND cert_name=?",
       [identityUri, keyId, certificateName.toUri()]);
  });
};

/*****************************************
 *            Delete Methods             *
 *****************************************/

/**
 * Delete a certificate.
 * @param {Name} certificateName The certificate name.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which fulfills when the certificate info is
 * deleted.
 */
BasicIdentityStorage.prototype.deleteCertificateInfoPromise = function
  (certificateName, useSync)
{
  if (useSync)
    return Promise.reject(new SecurityException(new Error
      ("BasicIdentityStorage.deleteCertificateInfoPromise is only supported for async")));

  if (certificateName.size() === 0)
    return

  return this.runPromise_
    ("DELETE FROM Certificate WHERE cert_name=?", certificateName.toUri());
};

/**
 * Delete a public key and related certificates.
 * @param {Name} keyName The key name.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which fulfills when the public key info is
 * deleted.
 */
BasicIdentityStorage.prototype.deletePublicKeyInfoPromise = function(keyName, useSync)
{
  if (useSync)
    return Promise.reject(new SecurityException(new Error
      ("BasicIdentityStorage.deletePublicKeyInfoPromise is only supported for async")));

  if (keyName.size() === 0)
    return Promise.resolve();

  var thisStorage = this;
  var keyId = keyName.get(-1).toEscapedString();
  var identityName = keyName.getPrefix(-1);

  return this.runPromise_
    ("DELETE FROM Certificate WHERE identity_name=? AND key_identifier=?",
     [identityName.toUri(), keyId])
  .then(function() {
    return thisStorage.runPromise_
      ("DELETE FROM Key WHERE identity_name=? and key_identifier=?",
       [identityName.toUri(), keyId]);
  });
};

/**
 * Delete an identity and related public keys and certificates.
 * @param {Name} identityName The identity name.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which fulfills when the identity info is deleted.
 */
BasicIdentityStorage.prototype.deleteIdentityInfoPromise = function
  (identityName, useSync)
{
  if (useSync)
    return Promise.reject(new SecurityException(new Error
      ("BasicIdentityStorage.deleteIdentityInfoPromise is only supported for async")));

  var thisStorage = this;
  var identity = identityName.toUri();

  return this.runPromise_
    ("DELETE FROM Certificate WHERE identity_name=?", identity)
  .then(function() {
    return thisStorage.runPromise_("DELETE FROM Key WHERE identity_name=?", identity);
  })
  .then(function() {
    return thisStorage.runPromise_("DELETE FROM Identity WHERE identity_name=?", identity);
  });
};

/**
 * Get the default directory that the constructor uses if databaseFilePath is
 * omitted. This does not try to create the directory.
 * @return {string} The default database directory path.
 */
BasicIdentityStorage.getDefaultDatabaseDirectoryPath = function()
{
  return path.join(BasicIdentityStorage.getUserHomePath(), ".ndn");
};

/**
 * Get the default database file path that the constructor uses if
 * databaseFilePath is omitted.
 * @return {string} The default database file path.
 */
BasicIdentityStorage.getDefaultDatabaseFilePath = function()
{
  return path.join
    (BasicIdentityStorage.getDefaultDatabaseDirectoryPath(),
     "ndnsec-public-info.db");
};

/**
 * Call Sqlite3Promise.runPromise, wrapping an Error in SecurityException.
 */
BasicIdentityStorage.prototype.runPromise_ = function(sql, params)
{
  return this.database_.runPromise(sql, params)
  .catch(function(error) {
    return Promise.reject(new SecurityException(error));
  });
};

/**
 * Call Sqlite3Promise.getPromise, wrapping an Error in SecurityException.
 */
BasicIdentityStorage.prototype.getPromise_ = function(sql, params)
{
  return this.database_.getPromise(sql, params)
  .catch(function(error) {
    return Promise.reject(new SecurityException(error));
  });
};

/**
 * Call Sqlite3Promise.eachPromise, wrapping an Error in SecurityException.
 */
BasicIdentityStorage.prototype.eachPromise_ = function(sql, params, onRow)
{
  return this.database_.eachPromise(sql, params, onRow)
  .catch(function(error) {
    return Promise.reject(new SecurityException(error));
  });
};

/**
 * Retrieve the user's current home directory
 * @return {string} path to the user's home directory
 */
BasicIdentityStorage.getUserHomePath = function() {
  return process.env.HOME || process.env.HOMEPATH || process.env.USERPROFILE;
};

BasicIdentityStorage.initializeDatabasePromise_ = function(database)
{
  // Check if the TpmInfo table exists.
  return database.getPromise
    ("SELECT name FROM sqlite_master WHERE type='table' And name='TpmInfo'")
  .then(function(row) {
    if (row)
      return Promise.resolve();
    else
      return database.runPromise(BasicIdentityStorage.INIT_TPM_INFO_TABLE);
  })
  .then(function() {
    // Check if the ID table exists.
    return database.getPromise
      ("SELECT name FROM sqlite_master WHERE type='table' And name='Identity'");
  })
  .then(function(row) {
    if (row)
      return Promise.resolve();
    else {
      return database.runPromise(BasicIdentityStorage.INIT_ID_TABLE1)
      .then(function() {
        return database.runPromise(BasicIdentityStorage.INIT_ID_TABLE2);
      });
    }
  })
  .then(function() {
    // Check if the Key table exists.
    return database.getPromise
      ("SELECT name FROM sqlite_master WHERE type='table' And name='Key'");
  })
  .then(function(row) {
    if (row)
      return Promise.resolve();
    else {
      return database.runPromise(BasicIdentityStorage.INIT_KEY_TABLE1)
      .then(function() {
        return database.runPromise(BasicIdentityStorage.INIT_KEY_TABLE2);
      });
    }
  })
  .then(function() {
    // Check if the Certificate table exists.
    return database.getPromise
      ("SELECT name FROM sqlite_master WHERE type='table' And name='Certificate'");
  })
  .then(function(row) {
    if (row)
      return Promise.resolve();
    else {
      return database.runPromise(BasicIdentityStorage.INIT_CERT_TABLE1)
      .then(function() {
        return database.runPromise(BasicIdentityStorage.INIT_CERT_TABLE2);
      })
      .then(function() {
        return database.runPromise(BasicIdentityStorage.INIT_CERT_TABLE3);
      });
    }
  });
};

BasicIdentityStorage.INIT_TPM_INFO_TABLE =
"CREATE TABLE IF NOT EXISTS                                           \n" +
"  TpmInfo(                                                           \n" +
"      tpm_locator BLOB NOT NULL,                                     \n" +
"      PRIMARY KEY (tpm_locator)                                      \n" +
"  );                                                                 \n" +
"                                                                     \n";

BasicIdentityStorage.INIT_ID_TABLE1 =
"CREATE TABLE IF NOT EXISTS                                           \n" +
"  Identity(                                                          \n" +
"      identity_name     BLOB NOT NULL,                               \n" +
"      default_identity  INTEGER DEFAULT 0,                           \n" +
"                                                                     \n" +
"      PRIMARY KEY (identity_name)                                    \n" +
"  );                                                                 \n" +
"                                                                     \n";
BasicIdentityStorage.INIT_ID_TABLE2 =
"CREATE INDEX identity_index ON Identity(identity_name);              \n";

BasicIdentityStorage.INIT_KEY_TABLE1 =
"CREATE TABLE IF NOT EXISTS                                           \n" +
"  Key(                                                               \n" +
"      identity_name     BLOB NOT NULL,                               \n" +
"      key_identifier    BLOB NOT NULL,                               \n" +
"      key_type          INTEGER,                                     \n" +
"      public_key        BLOB,                                        \n" +
"      default_key       INTEGER DEFAULT 0,                           \n" +
"      active            INTEGER DEFAULT 0,                           \n" +
"                                                                     \n" +
"      PRIMARY KEY (identity_name, key_identifier)                    \n" +
"  );                                                                 \n" +
"                                                                     \n";
BasicIdentityStorage.INIT_KEY_TABLE2 =
"CREATE INDEX key_index ON Key(identity_name);                        \n";

BasicIdentityStorage.INIT_CERT_TABLE1 =
"CREATE TABLE IF NOT EXISTS                                           \n" +
"  Certificate(                                                       \n" +
"      cert_name         BLOB NOT NULL,                               \n" +
"      cert_issuer       BLOB NOT NULL,                               \n" +
"      identity_name     BLOB NOT NULL,                               \n" +
"      key_identifier    BLOB NOT NULL,                               \n" +
"      not_before        TIMESTAMP,                                   \n" +
"      not_after         TIMESTAMP,                                   \n" +
"      certificate_data  BLOB NOT NULL,                               \n" +
"      valid_flag        INTEGER DEFAULT 1,                           \n" +
"      default_cert      INTEGER DEFAULT 0,                           \n" +
"                                                                     \n" +
"      PRIMARY KEY (cert_name)                                        \n" +
"  );                                                                 \n" +
"                                                                     \n";
BasicIdentityStorage.INIT_CERT_TABLE2 =
"CREATE INDEX cert_index ON Certificate(cert_name);           \n";
BasicIdentityStorage.INIT_CERT_TABLE3 =
"CREATE INDEX subject ON Certificate(identity_name);          \n";
