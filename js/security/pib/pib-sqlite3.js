/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/pib/pib-sqlite3.cpp
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
var CertificateV2 = require('../v2/certificate-v2.js').CertificateV2; /** @ignore */
var Pib = require('./pib.js').Pib; /** @ignore */
var PibKey = require('./pib-key.js').PibKey; /** @ignore */
var Sqlite3Promise = require('../../util/sqlite3-promise.js').Sqlite3Promise; /** @ignore */
var PibImpl = require('./pib-impl.js').PibImpl; /** @ignore */
var path = require('path');

/**
 * PibSqlite3 extends PibImpl and is used by the Pib class as an implementation
 * of a PIB based on an SQLite3 database. All the contents in the PIB are stored
 * in an SQLite3 database file. This provides more persistent storage than
 * PibMemory.
 *
 * Create a new PibSqlite3 to work with an SQLite3 file. This assumes that the
 * database directory does not contain a PIB database of an older version.
 *
 * @param {string} databaseDirectoryPath (optional) The directory where the
 * database file is located. If omitted, use $HOME/.ndn . If the directory does
 * not exist, this does not try to create it.
 * @param {string} databaseFilename (optional) The name if the database file in
 * the databaseDirectoryPath. If databaseFilename is supplied, then
 * databaseDirectoryPath must also be supplied. If omitted, use "pib.db".
 * @param {function} initialCheckPromise (optional) If supplied, then after
 * initializing the database this calls initialCheckPromise() which returns a
 * Promise that resolves when the initial check passes or is rejected for a
 * problem.
 * @constructor
 */
var PibSqlite3 = function PibSqlite3
  (databaseDirectoryPath, databaseFilename, initialCheckPromise)
{
  // Call the base constructor.
  PibImpl.call(this);

  // Temporarlity reassign to resolve the different overloaded forms.
  var arg1 = databaseDirectoryPath;
  var arg2 = databaseFilename;
  var arg3 = initialCheckPromise;
  // arg1,                  arg2,                arg3 may be:
  // databaseDirectoryPath, databaseFilename,    initialCheckPromise
  // databaseDirectoryPath, databaseFilename,    null
  // databaseDirectoryPath, initialCheckPromise, null
  // databaseDirectoryPath, null,                null
  // initialCheckPromise,   null,                null
  // null,                  null,                null
  if (typeof arg1 === "string")
    databaseDirectoryPath = arg1;
  else
    databaseDirectoryPath = undefined;

  if (typeof arg2 === "string")
    databaseFilename = arg2;
  else
    databaseFilename = undefined;

  if (typeof arg1 === "function")
    initialCheckPromise = arg1;
  else if (typeof arg2 === "function")
    initialCheckPromise = arg2;
  else if (typeof arg3 === "function")
    initialCheckPromise = arg3;
  else
    initialCheckPromise = undefined;

  if (databaseDirectoryPath == undefined || databaseDirectoryPath == "")
    databaseDirectoryPath = PibSqlite3.getDefaultDatabaseDirectoryPath();
  if (databaseFilename == undefined || databaseFilename == "")
    databaseFilename = "pib.db";

  var initializeDatabasePromise;
  if (initialCheckPromise) {
    // Call our initializeDatabasePromise_ and then initialCheckPromise.
    initializeDatabasePromise = function(database) {
      return PibSqlite3.initializeDatabasePromise_(database)
      .then(function() { return initialCheckPromise(); });
    };
  }
  else
    initializeDatabasePromise = PibSqlite3.initializeDatabasePromise_;

  this.database_ = new Sqlite3Promise
    (path.join(databaseDirectoryPath, databaseFilename),
     initializeDatabasePromise);
};

PibSqlite3.prototype = new PibImpl();
PibSqlite3.prototype.name = "PibSqlite3";

exports.PibSqlite3 = PibSqlite3;

PibSqlite3.getScheme = function() { return "pib-sqlite3"; };

// TpmLocator management.

/**
 * Set the corresponding TPM information to tpmLocator. This method does not
 * reset the contents of the PIB.
 * @param {string} tpmLocator The TPM locator string.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which fulfills when the TPM locator is set.
 */
PibSqlite3.prototype.setTpmLocatorPromise = function(tpmLocator, useSync)
{
  if (useSync)
    return Promise.reject(new PibImpl.Error(new Error
      ("PibSqlite3.setTpmLocatorPromise is only supported for async")));

  var thisPib = this;
  return this.getTpmLocatorPromise()
  .then(function(locator) {
    if (locator == "")
      return thisPib.runPromise_
        ("INSERT INTO tpmInfo (tpm_locator) values (?)", tpmLocator);
    else
      return thisPib.runPromise_("UPDATE tpmInfo SET tpm_locator=?", tpmLocator);
  });
};

/**
 * Get the TPM Locator.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which returns the TPM locator string.
 */
PibSqlite3.prototype.getTpmLocatorPromise = function(useSync)
{
  if (useSync)
    return Promise.reject(new PibImpl.Error(new Error
      ("PibSqlite3.getTpmLocatorPromise is only supported for async")));

  return this.getPromise_("SELECT tpm_locator FROM tpmInfo")
  .then(function(row) {
    if (row)
      return Promise.resolve(row.tpm_locator);
    else
      return Promise.resolve("");
  });
};

// Identity management.

/**
 * Check for the existence of an identity.
 * @param {Name} identityName The name of the identity.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which returns true if the identity exists,
 * otherwise false.
 */
PibSqlite3.prototype.hasIdentityPromise = function(identityName, useSync)
{
  if (useSync)
    return Promise.reject(new PibImpl.Error(new Error
      ("PibSqlite3.hasIdentityPromise is only supported for async")));

  return this.getPromise_
    ("SELECT id FROM identities WHERE identity=?",
     identityName.wireEncode().buf())
  .then(function(row) {
    return Promise.resolve(!!row);
  });
};

/**
 * Add the identity. If the identity already exists, do nothing. If no default
 * identity has been set, set the added identity as the default.
 * @param {Name} identityName The name of the identity to add. This copies the
 * name.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which fulfills when the identity is added.
 */
PibSqlite3.prototype.addIdentityPromise = function(identityName, useSync)
{
  if (useSync)
    return Promise.reject(new PibImpl.Error(new Error
      ("PibSqlite3.addIdentityPromise is only supported for async")));

  var thisPib = this;
  return this.hasIdentityPromise(identityName)
  .then(function(hasIdentity) {
    if (!hasIdentity)
      return thisPib.runPromise_
        ("INSERT INTO identities (identity) values (?)",
         identityName.wireEncode().buf());
    else
      return Promise.resolve();
  })
  .then(function() {
    return thisPib.hasDefaultIdentityPromise_();
  })
  .then(function(hasDefaultIdentity) {
    if (!hasDefaultIdentity)
      return thisPib.setDefaultIdentityPromise(identityName);
    else
      return Promise.resolve();
  });
};

/**
 * Remove the identity and its related keys and certificates. If the default
 * identity is being removed, no default identity will be selected. If the
 * identity does not exist, do nothing.
 * @param {Name} identityName The name of the identity to remove.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which fulfills when the identity is removed.
 */
PibSqlite3.prototype.removeIdentityPromise = function(identityName, useSync)
{
  if (useSync)
    return Promise.reject(new PibImpl.Error(new Error
      ("PibSqlite3.removeIdentityPromise is only supported for async")));

  var thisPib = this;
  var identityBytes = identityName.wireEncode().buf();

  // We don't use triggers, so manually delete from keys and certificates.
  // First get the key ids.
  var keyIds = [];

  return this.eachPromise_
    ("SELECT keys.id " +
     "FROM keys JOIN identities ON keys.identity_id=identities.id " +
     "WHERE identities.identity=?",
     identityBytes,
     function(err, row) { keyIds.push(row.id); })
  .then(function() {
    // Get the promises to use in Promise.all.
    var promises = [];
    for (var i = 0; i < keyIds.length; ++i)
      promises.push(thisPib.runPromise_
       ("DELETE FROM certificates WHERE key_id=?", keyIds[i]));
    return Promise.all(promises);
  })
  .then(function() {
    // Get the promises to use in Promise.all.
    var promises = [];
    for (var i = 0; i < keyIds.length; ++i)
      promises.push(thisPib.runPromise_
       ("DELETE FROM keys WHERE id=?", keyIds[i]));
    return Promise.all(promises);
  })
  .then(function() {
    // Now, delete from identities.
    return thisPib.runPromise_
      ("DELETE FROM identities WHERE identity=?", identityBytes);
  });
};

/**
 * Erase all certificates, keys, and identities.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which fulfills when the identities are cleared.
 */
PibSqlite3.prototype.clearIdentitiesPromise = function(useSync)
{
  if (useSync)
    return Promise.reject(new PibImpl.Error(new Error
      ("PibSqlite3.clearIdentitiesPromise is only supported for async")));

  var thisPib = this;
  // We don't use triggers, so manually delete from keys and certificates.
  return this.runPromise_("DELETE FROM certificates")
  .then(function() {
    return thisPib.runPromise_("DELETE FROM keys");
  })
  .then(function() {
    // Now, delete from identities.
    return thisPib.runPromise_("DELETE FROM identities");
  });
};

/**
 * Get the names of all the identities.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which returns a fresh set of identity names
 * as an array of Name. The Name objects are fresh copies.
 */
PibSqlite3.prototype.getIdentitiesPromise = function(useSync)
{
  if (useSync)
    return Promise.reject(new PibImpl.Error(new Error
      ("PibSqlite3.getIdentitiesPromise is only supported for async")));

  var identities = [];

  return this.eachPromise_
    ("SELECT identity FROM identities", null, function(err, row) {
      var name = new Name();
      name.wireDecode(row.identity);
      identities.push(name);
  })
  .then(function() {
    return Promise.resolve(identities);
  });
};

/**
 * Set the identity with the identityName as the default identity. If the
 * identity with identityName does not exist, then it will be created.
 * @param {Name} identityName The name for the default identity. This copies the
 * name.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which fulfills when the default identity is
 * set.
 */
PibSqlite3.prototype.setDefaultIdentityPromise = function(identityName, useSync)
{
  if (useSync)
    return Promise.reject(new PibImpl.Error(new Error
      ("PibSqlite3.setDefaultIdentityPromise is only supported for async")));

  var thisPib = this;
  return this.hasIdentityPromise(identityName)
  .then(function(hasIdentity) {
    if (!hasIdentity)
      return thisPib.runPromise_
        ("INSERT INTO identities (identity) values (?)",
         identityName.wireEncode().buf());
    else
      return Promise.resolve();
  })
  .then(function() {
    // We don't use a trigger, so manually reset the previous default identity.
    return thisPib.runPromise_
      ("UPDATE identities SET is_default=0 WHERE is_default=1");
  })
  .then(function() {
    // Now set the current default identity.
    return thisPib.runPromise_
      ("UPDATE identities SET is_default=1 WHERE identity=?",
       identityName.wireEncode().buf());
  });
};

/**
 * Get the default identity.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which returns the Name of the default
 * identity as a fresh copy, or a promise rejected with Pib.Error for no default
 * identity.
 */
PibSqlite3.prototype.getDefaultIdentityPromise = function(useSync)
{
  if (useSync)
    return Promise.reject(new PibImpl.Error(new Error
      ("PibSqlite3.getDefaultIdentityPromise is only supported for async")));

  return this.getPromise_("SELECT identity FROM identities WHERE is_default=1")
  .then(function(row) {
    if (row) {
      var name = new Name();
      name.wireDecode(row.identity);
      return Promise.resolve(name);
    }
    else
      return Promise.reject(new Pib.Error(new Error("No default identity")));
  });
};

// Key management.

/**
 * Check for the existence of a key with keyName.
 * @param {Name} keyName The name of the key.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which returns true if the key exists,
 * otherwise false. Return false if the identity does not exist.
 */
PibSqlite3.prototype.hasKeyPromise = function(keyName, useSync)
{
  if (useSync)
    return Promise.reject(new PibImpl.Error(new Error
      ("PibSqlite3.hasKeyPromise is only supported for async")));

  return this.getPromise_
    ("SELECT id FROM keys WHERE key_name=?", keyName.wireEncode().buf())
  .then(function(row) {
    return Promise.resolve(!!row);
  });
};

/**
 * Add the key. If a key with the same name already exists, overwrite the key.
 * If the identity does not exist, it will be created. If no default key for the
 * identity has been set, then set the added key as the default for the
 * identity. If no default identity has been set, identity becomes the default.
 * @param {Name} identityName The name of the identity that the key belongs to.
 * This copies the name.
 * @param {Name} keyName The name of the key. This copies the name.
 * @param {Buffer} key The public key bits. This copies the array.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which fulfills when the key is added.
 */
PibSqlite3.prototype.addKeyPromise = function(identityName, keyName, key, useSync)
{
  if (useSync)
    return Promise.reject(new PibImpl.Error(new Error
      ("PibSqlite3.addKeyPromise is only supported for async")));

  var thisPib = this;

  // Ensure the identity exists.
  return this.addIdentityPromise(identityName)
  .then(function() {
    return thisPib.hasKeyPromise(keyName);
  })
  .then(function(hasKey) {
    if (!hasKey)
      return thisPib.runPromise_
        ("INSERT INTO keys (identity_id, key_name, key_bits) " +
         "VALUES ((SELECT id FROM identities WHERE identity=?), ?, ?)",
         [identityName.wireEncode().buf(),
          keyName.wireEncode().buf(),
          key]);
    else
      return thisPib.runPromise_
        ("UPDATE keys SET key_bits=? WHERE key_name=?",
         [key, keyName.wireEncode().buf()]);
  })
  .then(function() {
    return thisPib.hasDefaultKeyOfIdentityPromise_(identityName);
  })
  .then(function(hasDefault) {
    if (!hasDefault)
      return thisPib.setDefaultKeyOfIdentityPromise(identityName, keyName);
    else
      return Promise.resolve();
  });
};

/**
 * Remove the key with keyName and its related certificates. If the key does not
 * exist, do nothing.
 * @param {Name} keyName The name of the key.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which fulfills when the key is removed.
 */
PibSqlite3.prototype.removeKeyPromise = function(keyName, useSync)
{
  if (useSync)
    return Promise.reject(new PibImpl.Error(new Error
      ("PibSqlite3.removeKeyPromise is only supported for async")));

  var thisPib = this;
  var keyNameBytes = keyName.wireEncode().buf();

  // We don't use triggers, so manually delete from certificates.
  return this.runPromise_
    ("DELETE FROM certificates WHERE key_id=(SELECT id FROM keys WHERE key_name=?)",
     keyNameBytes)
  .then(function() {
    // Now, delete from keys.
    return thisPib.runPromise_
      ("DELETE FROM keys WHERE key_name=?", keyNameBytes);
  });
};

/**
 * Get the key bits of a key with name keyName.
 * @param {Name} keyName The name of the key.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which returns the key bits as a Blob, or a
 * promise rejected with Pib.Error if the key does not exist.
 */
PibSqlite3.prototype.getKeyBitsPromise = function(keyName, useSync)
{
  if (useSync)
    return Promise.reject(new PibImpl.Error(new Error
      ("PibSqlite3.getKeyBitsPromise is only supported for async")));

  return this.getPromise_
    ("SELECT key_bits FROM keys WHERE key_name=?", keyName.wireEncode().buf())
  .then(function(row) {
    if (row)
      return Promise.resolve(new Blob(row.key_bits, false));
    else
      return Promise.reject(new Pib.Error(new Error
        ("Key `" + keyName.toUri() + "` does not exist")));
  });
};

/**
 * Get all the key names of the identity with the name identityName. The
 * returned key names can be used to create a KeyContainer. With a key name and
 * a backend implementation, one can create a Key front end instance.
 * @param {Name} identityName The name of the identity.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return SyncPromise} A promise which returns the set of key names as an array
 * of Name. The Name objects are fresh copies. If the identity does not exist,
 * return an empty array.
 */
PibSqlite3.prototype.getKeysOfIdentityPromise = function(identityName, useSync)
{
  if (useSync)
    return Promise.reject(new PibImpl.Error(new Error
      ("PibSqlite3.getKeysOfIdentityPromise is only supported for async")));

  var keyNames = [];

  return this.eachPromise_
    ("SELECT key_name " +
     "FROM keys JOIN identities ON keys.identity_id=identities.id " +
     "WHERE identities.identity=?",
     identityName.wireEncode().buf(),
     function(err, row) {
      var name = new Name();
      name.wireDecode(row.key_name);
      keyNames.push(name);
  })
  .then(function() {
    return Promise.resolve(keyNames);
  });
};

/**
 * Set the key with keyName as the default key for the identity with name
 * identityName.
 * @param {Name} identityName The name of the identity. This copies the name.
 * @param {Name} keyName The name of the key. This copies the name.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which fulfills when the default key is set,
 * or a promise rejected with Pib.Error if the key does not exist.
 */
PibSqlite3.prototype.setDefaultKeyOfIdentityPromise = function
  (identityName, keyName, useSync)
{
  if (useSync)
    return Promise.reject(new PibImpl.Error(new Error
      ("PibSqlite3.setDefaultKeyOfIdentityPromise is only supported for async")));

  var thisPib = this;
  return this.hasKeyPromise(keyName)
  .then(function(hasKey) {
    if (!hasKey)
      return Promise.reject(new Pib.Error(new Error
        ("Key `" + keyName.toUri() + "` does not exist")));
    else
      return Promise.resolve();
  })
  .then(function() {
    // We don't use a trigger, so manually reset the previous default key.
    return thisPib.runPromise_
      ("UPDATE keys SET is_default=0 WHERE is_default=1");
  })
  .then(function() {
    // Now set the current default key.
    return thisPib.runPromise_
      ("UPDATE keys SET is_default=1 WHERE key_name=?",
       keyName.wireEncode().buf());
  });
};

/**
 * Get the name of the default key for the identity with name identityName.
 * @param {Name} identityName The name of the identity.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which returns the name of the default key as
 * a fresh copy, or a promise rejected with Pib.Error if the identity does not
 * exist.
 */
PibSqlite3.prototype.getDefaultKeyOfIdentityPromise = function
  (identityName, useSync)
{
  if (useSync)
    return Promise.reject(new PibImpl.Error(new Error
      ("PibSqlite3.getDefaultKeyOfIdentityPromise is only supported for async")));

  var thisPib = this;

  return this.hasIdentityPromise(identityName)
  .then(function(hasIdentity) {
    if (!hasIdentity)
      return Promise.reject(new Pib.Error(new Error
        ("Identity `" + identityName.toUri() + "` does not exist")));
    else
      return Promise.resolve();
  })
  .then(function() {
    return thisPib.getPromise_
      ("SELECT key_name " +
       "FROM keys JOIN identities ON keys.identity_id=identities.id " +
       "WHERE identities.identity=? AND keys.is_default=1",
       identityName.wireEncode().buf());
  })
  .then(function(row) {
    if (row) {
      var name = new Name();
      name.wireDecode(row.key_name);
      return Promise.resolve(name);
    }
    else
      return Promise.reject(new Pib.Error(new Error
        ("No default key for identity `" + identityName.toUri() + "`")));
  });
};

// Certificate management.

/**
 * Check for the existence of a certificate with name certificateName.
 * @param {Name} certificateName The name of the certificate.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which returns true if the certificate exists,
 * otherwise false.
 */
PibSqlite3.prototype.hasCertificatePromise = function(certificateName, useSync)
{
  if (useSync)
    return Promise.reject(new PibImpl.Error(new Error
      ("PibSqlite3.hasCertificatePromise is only supported for async")));

  return this.getPromise_
    ("SELECT id FROM certificates WHERE certificate_name=?",
     certificateName.wireEncode().buf())
  .then(function(row) {
    return Promise.resolve(!!row);
  });
};

/**
 * Add the certificate. If a certificate with the same name (without implicit
 * digest) already exists, then overwrite the certificate. If the key or
 * identity does not exist, they will be created. If no default certificate for
 * the key has been set, then set the added certificate as the default for the
 * key. If no default key was set for the identity, it will be set as the
 * default key for the identity. If no default identity was selected, the
 * certificate's identity becomes the default.
 * @param {CertificateV2} certificate The certificate to add. This copies the
 * object.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which fulfills when the certificate is added.
 */
PibSqlite3.prototype.addCertificatePromise = function(certificate, useSync)
{
  if (useSync)
    return Promise.reject(new PibImpl.Error(new Error
      ("PibSqlite3.addCertificatePromise is only supported for async")));

  var thisPib = this;

  // Ensure the key exists.
  var content = certificate.getContent()
  return this.addKeyPromise
    (certificate.getIdentity(), certificate.getKeyName(), content.buf())
  .then(function() {
    return thisPib.hasCertificatePromise(certificate.getName());
  })
  .then(function(hasCertificate) {
    if (!hasCertificate)
      return thisPib.runPromise_
        ("INSERT INTO certificates " +
         "(key_id, certificate_name, certificate_data) " +
         "VALUES ((SELECT id FROM keys WHERE key_name=?), ?, ?)",
         [certificate.getKeyName().wireEncode().buf(),
          certificate.getName().wireEncode().buf(),
          certificate.wireEncode().buf()]);
    else
      return thisPib.runPromise_
        ("UPDATE certificates SET certificate_data=? WHERE certificate_name=?",
         [certificate.wireEncode().buf(),
          certificate.getName().wireEncode().buf()]);
  })
  .then(function() {
    return thisPib.hasDefaultCertificateOfKeyPromise_(certificate.getKeyName());
  })
  .then(function(hasDefault) {
    if (!hasDefault)
      return thisPib.setDefaultCertificateOfKeyPromise
        (certificate.getKeyName(), certificate.getName());
    else
      return Promise.resolve();
  });
};

/**
 * Remove the certificate with name certificateName. If the certificate does not
 * exist, do nothing.
 * @param {Name} certificateName The name of the certificate.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which fulfills when the certificate is
 * removed.
 */
PibSqlite3.prototype.removeCertificatePromise = function(certificateName, useSync)
{
  if (useSync)
    return Promise.reject(new PibImpl.Error(new Error
      ("PibSqlite3.removeCertificatePromise is only supported for async")));

  return this.runPromise_
    ("DELETE FROM certificates WHERE certificate_name=?",
     certificateName.wireEncode().buf());
};

/**
 * Get the certificate with name certificateName.
 * @param {Name} certificateName The name of the certificate.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which returns the CertificateV2, or a promise
 * rejected with Pib.Error if the certificate does not exist.
 */
PibSqlite3.prototype.getCertificatePromise = function(certificateName, useSync)
{
  if (useSync)
    return Promise.reject(new PibImpl.Error(new Error
      ("PibSqlite3.getCertificatePromise is only supported for async")));

  return this.getPromise_
    ("SELECT certificate_data FROM certificates WHERE certificate_name=?",
     certificateName.wireEncode().buf())
  .then(function(row) {
    if (row) {
      var certificate = new CertificateV2();
      certificate.wireDecode(row.certificate_data);
      return Promise.resolve(certificate);
    }
    else
      return Promise.reject(new Pib.Error(new Error
        ("Certificate `" + certificateName.toUri() + "` does not exit")));
  });
};

/**
 * Get a list of certificate names of the key with id keyName. The returned
 * certificate names can be used to create a PibCertificateContainer. With a
 * certificate name and a backend implementation, one can obtain the certificate.
 * @param {Name} keyName The name of the key.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which returns the set of certificate names as
 * an array of Name. The Name objects are fresh copies. If the key does not
 * exist, return an empty array.
 */
PibSqlite3.prototype.getCertificatesOfKeyPromise = function(keyName, useSync)
{
  if (useSync)
    return Promise.reject(new PibImpl.Error(new Error
      ("PibSqlite3.getCertificatesOfKeyPromise is only supported for async")));

  var certNames = [];

  return this.eachPromise_
    ("SELECT certificate_name " +
     "FROM certificates JOIN keys ON certificates.key_id=keys.id " +
     "WHERE keys.key_name=?",
     keyName.wireEncode().buf(),
     function(err, row) {
      var name = new Name();
      name.wireDecode(row.certificate_name);
      certNames.push(name);
  })
  .then(function() {
    return Promise.resolve(certNames);
  });
};

/**
 * Set the cert with name certificateName as the default for the key with
 * keyName.
 * @param {Name} keyName The name of the key.
 * @param {Name} certificateName The name of the certificate. This copies the
 * name.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which fulfills when the default certificate
 * is set, or a promise rejected with Pib.Error if the certificate with name
 * certificateName does not exist.
 */
PibSqlite3.prototype.setDefaultCertificateOfKeyPromise = function
  (keyName, certificateName, useSync)
{
  if (useSync)
    return Promise.reject(new PibImpl.Error(new Error
      ("PibSqlite3.setDefaultCertificateOfKeyPromise is only supported for async")));

  var thisPib = this;
  return this.hasCertificatePromise(certificateName)
  .then(function(hasCertificate) {
    if (!hasCertificate)
      return Promise.reject(new Pib.Error(new Error
        ("Certificate `" + certificateName.toUri() + "` does not exist")));
    else
      return Promise.resolve();
  })
  .then(function() {
    // We don't use a trigger, so manually reset the previous default certificate.
    return thisPib.runPromise_
      ("UPDATE certificates SET is_default=0 WHERE is_default=1");
  })
  .then(function() {
    // Now set the current default certificate.
    return thisPib.runPromise_
      ("UPDATE certificates SET is_default=1 WHERE certificate_name=?",
       certificateName.wireEncode().buf());
  });
};

/**
 * Get the default certificate for the key with eyName.
 * @param {Name} keyName The name of the key.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which returns a copy of the default
 * CertificateV2, or a promise rejected with Pib.Error if the default
 * certificate does not exist.
 */
PibSqlite3.prototype.getDefaultCertificateOfKeyPromise = function(keyName, useSync)
{
  if (useSync)
    return Promise.reject(new PibImpl.Error(new Error
      ("PibSqlite3.getDefaultCertificateOfKeyPromise is only supported for async")));

  return this.getPromise_
    ("SELECT certificate_data " +
     "FROM certificates JOIN keys ON certificates.key_id=keys.id " +
     "WHERE certificates.is_default=1 AND keys.key_name=?",
     keyName.wireEncode().buf())
  .then(function(row) {
    if (row) {
      var certificate = new CertificateV2();
      certificate.wireDecode(row.certificate_data);
      return Promise.resolve(certificate);
    }
    else
      return Promise.reject(new Pib.Error(new Error
        ("No default certificate for key `" + keyName.toUri() + "`")));
  });
};

/**
 * Get the default that the constructor uses if databaseDirectoryPath is
 * omitted. This does not try to create the directory.
 * @return {string} The default database directory path.
 */
PibSqlite3.getDefaultDatabaseDirectoryPath = function()
{
  var home = process.env.HOME || process.env.HOMEPATH || process.env.USERPROFILE;
  return path.join(home, ".ndn");
};

/**
 * Get the default database file path that the constructor uses if
 * databaseDirectoryPath and databaseFilename are omitted.
 * @return {string} The default database file path.
 */
PibSqlite3.getDefaultDatabaseFilePath = function()
{
  return path.join(PibSqlite3.getDefaultDatabaseDirectoryPath(), "pib.db");
};

/**
 * Check if there is a default identity.
 * @return {Promise} A promise which returns true if there is a default identity.
 */
PibSqlite3.prototype.hasDefaultIdentityPromise_ = function()
{
  return this.getPromise_
    ("SELECT identity FROM identities WHERE is_default=1")
  .then(function(row) {
    return Promise.resolve(!!row);
  });
};

/**
 * Check if there is a default key for the identity with identityName.
 * @param {Name} identityName The identity Name.
 * @return {Promise} A promise which returns true if there is a default key.
 */
PibSqlite3.prototype.hasDefaultKeyOfIdentityPromise_ = function(identityName)
{
  return this.getPromise_
    ("SELECT key_name " +
     "FROM keys JOIN identities ON keys.identity_id=identities.id " +
     "WHERE identities.identity=? AND keys.is_default=1",
     identityName.wireEncode().buf())
  .then(function(row) {
    return Promise.resolve(!!row);
  });
};

/**
 * Check if there is a default certificate for the key with keyName.
 * @param {Name} keyName The key Name.
 * @return {Promise} A promise which returns true if there is a default
 * certificate.
 */
PibSqlite3.prototype.hasDefaultCertificateOfKeyPromise_ = function(keyName)
{
  return this.getPromise_
    ("SELECT certificate_data " +
     "FROM certificates JOIN keys ON certificates.key_id=keys.id " +
     "WHERE certificates.is_default=1 AND keys.key_name=?",
     keyName.wireEncode().buf())
  .then(function(row) {
    return Promise.resolve(!!row);
  });
};

/**
 * Call Sqlite3Promise.runPromise, wrapping an Error in PibImpl.Error.
 */
PibSqlite3.prototype.runPromise_ = function(sql, params)
{
  return this.database_.runPromise(sql, params)
  .catch(function(error) {
    return Promise.reject(new PibImpl.Error(error));
  });
};

/**
 * Call Sqlite3Promise.getPromise, wrapping an Error in PibImpl.Error.
 */
PibSqlite3.prototype.getPromise_ = function(sql, params)
{
  return this.database_.getPromise(sql, params)
  .catch(function(error) {
    return Promise.reject(new PibImpl.Error(error));
  });
};

/**
 * Call Sqlite3Promise.eachPromise, wrapping an Error in PibImpl.Error.
 */
PibSqlite3.prototype.eachPromise_ = function(sql, params, onRow)
{
  return this.database_.eachPromise(sql, params, onRow)
  .catch(function(error) {
    return Promise.reject(new PibImpl.Error(error));
  });
};

PibSqlite3.initializeDatabasePromise_ = function(database)
{
  return database.runPromise(PibSqlite3.INITIALIZATION1)
  .then(function() {
    return database.runPromise(PibSqlite3.INITIALIZATION2);
  })
  .then(function() {
    return database.runPromise(PibSqlite3.INITIALIZATION3);
  })
  .then(function() {
    return database.runPromise(PibSqlite3.INITIALIZATION4);
  })
  .then(function() {
    return database.runPromise(PibSqlite3.INITIALIZATION5);
  })
  .then(function() {
    return database.runPromise(PibSqlite3.INITIALIZATION6);
  })
  .then(function() {
    return database.runPromise(PibSqlite3.INITIALIZATION7);
  });
};

PibSqlite3.INITIALIZATION1 =
"CREATE TABLE IF NOT EXISTS                         \n" +
"  tpmInfo(                                         \n" +
"    tpm_locator           BLOB                     \n" +
"  );                                               \n";
PibSqlite3.INITIALIZATION2 =
"CREATE TABLE IF NOT EXISTS                         \n" +
"  identities(                                      \n" +
"    id                    INTEGER PRIMARY KEY,     \n" +
"    identity              BLOB NOT NULL,           \n" +
"    is_default            INTEGER DEFAULT 0        \n" +
"  );                                               \n";
PibSqlite3.INITIALIZATION3 =
"CREATE UNIQUE INDEX IF NOT EXISTS                  \n" +
"  identityIndex ON identities(identity);           \n";
PibSqlite3.INITIALIZATION4 =
"CREATE TABLE IF NOT EXISTS                         \n" +
"  keys(                                            \n" +
"    id                    INTEGER PRIMARY KEY,     \n" +
"    identity_id           INTEGER NOT NULL,        \n" +
"    key_name              BLOB NOT NULL,           \n" +
"    key_bits              BLOB NOT NULL,           \n" +
"    is_default            INTEGER DEFAULT 0        \n" +
"  );                                               \n";
PibSqlite3.INITIALIZATION5 =
"CREATE UNIQUE INDEX IF NOT EXISTS                  \n" +
"  keyIndex ON keys(key_name);                      \n";
PibSqlite3.INITIALIZATION6 =
"CREATE TABLE IF NOT EXISTS                         \n" +
"  certificates(                                    \n" +
"    id                    INTEGER PRIMARY KEY,     \n" +
"    key_id                INTEGER NOT NULL,        \n" +
"    certificate_name      BLOB NOT NULL,           \n" +
"    certificate_data      BLOB NOT NULL,           \n" +
"    is_default            INTEGER DEFAULT 0        \n" +
"  );                                               \n";
PibSqlite3.INITIALIZATION7 =
"CREATE UNIQUE INDEX IF NOT EXISTS                  \n" +
"  certIndex ON certificates(certificate_name);     \n";
