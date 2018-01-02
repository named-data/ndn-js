/**
 * Copyright (C) 2015-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
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

// Don't require modules since this is meant for the browser, not Node.js.

/**
 * IndexedDbIdentityStorage extends IdentityStorage and implements its methods
 * to store identity, public key and certificate objects using the browser's
 * IndexedDB service.
 * @constructor
 */
var IndexedDbIdentityStorage = function IndexedDbIdentityStorage()
{
  IdentityStorage.call(this);

  this.database = new Dexie("ndnsec-public-info");
  // The database schema imitates MemoryIdentityStorage.
  this.database.version(1).stores({
    // A table for global values. It currently only has the defaultIdentityUri.
    // "key" is the key like "defaultIdentityUri" // string
    // "value" is the value. For "defaultIdentityUri" the value is the
    //         default identity name URI, or absent if not defined. // string
    globals: "key",

    // "identityNameUri" is the identity name URI          // string
    // "defaultKeyUri" is the default key name URI or null // string
    identity: "identityNameUri",

    // "keyNameUri" is the key name URI                             // string
    // "keyType" is the type of the public key            // number from KeyType
    // "keyDer" is the public key DER                               // Uint8Array
    // "defaultCertificateUri" is the default cert name URI or null // string
    publicKey: "keyNameUri",

    // "certificateNameUri" is the certificate name URI // string
    // "encoding" is the certificate wire encoding      // Uint8Array
    certificate: "certificateNameUri"
  });
  this.database.open();
};

IndexedDbIdentityStorage.prototype = new IdentityStorage();
IndexedDbIdentityStorage.prototype.name = "IndexedDbIdentityStorage";

/**
 * Check if the specified identity already exists.
 * @param {Name} identityName The identity name.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which returns true if the identity exists.
 */
IndexedDbIdentityStorage.prototype.doesIdentityExistPromise = function
  (identityName, useSync)
{
  if (useSync)
    return Promise.reject(new SecurityException(new Error
      ("IndexedDbIdentityStorage.doesIdentityExistPromise is only supported for async")));

  return this.database.identity.where("identityNameUri").equals
    (identityName.toUri())
  .count()
  .then(function(count) {
    return Promise.resolve(count > 0);
  });
};

/**
 * Add a new identity. Do nothing if the identity already exists.
 * @param {Name} identityName The identity name to be added.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which fulfills when the identity is added.
 */
IndexedDbIdentityStorage.prototype.addIdentityPromise = function
  (identityName, useSync)
{
  if (useSync)
    return Promise.reject(new SecurityException(new Error
      ("IndexedDbIdentityStorage.addIdentityPromise is only supported for async")));

  var thisStorage = this;
  return this.doesIdentityExistPromise(identityName)
  .then(function(exists) {
    if (exists)
      // Do nothing.
      return Promise.resolve();

    return thisStorage.database.identity.put
      ({ identityNameUri: identityName.toUri(), defaultKeyUri: null });
  });
};

/**
 * Check if the specified key already exists.
 * @param {Name} keyName The name of the key.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which returns true if the key exists.
 */
IndexedDbIdentityStorage.prototype.doesKeyExistPromise = function
  (keyName, useSync)
{
  if (useSync)
    return Promise.reject(new SecurityException(new Error
      ("IndexedDbIdentityStorage.doesKeyExistPromise is only supported for async")));

  return this.database.publicKey.where("keyNameUri").equals(keyName.toUri())
  .count()
  .then(function(count) {
    return Promise.resolve(count > 0);
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
IndexedDbIdentityStorage.prototype.addKeyPromise = function
  (keyName, keyType, publicKeyDer, useSync)
{
  if (useSync)
    return Promise.reject(new SecurityException(new Error
      ("IndexedDbIdentityStorage.addKeyPromise is only supported for async")));

  if (keyName.size() === 0)
    return Promise.resolve();

  var thisStorage = this;
  return this.doesKeyExistPromise(keyName)
  .then(function(exists) {
    if (exists)
      return Promise.resolve();

    var identityName = keyName.getPrefix(-1);
    return thisStorage.addIdentityPromise(identityName)
    .then(function() {
      return thisStorage.database.publicKey.put
        ({ keyNameUri: keyName.toUri(), keyType: keyType,
           keyDer: new Blob(publicKeyDer, true).buf(),
           defaultCertificate: null });
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
IndexedDbIdentityStorage.prototype.getKeyPromise = function(keyName, useSync)
{
  if (useSync)
    return Promise.reject(new SecurityException(new Error
      ("IndexedDbIdentityStorage.getKeyPromise is only supported for async")));

  if (keyName.size() === 0)
    return Promise.reject(new SecurityException(new Error
      ("IndexedDbIdentityStorage.getKeyPromise: Empty keyName")));

  return this.database.publicKey.get(keyName.toUri())
  .then(function(publicKeyEntry) {
    if (publicKeyEntry)
      return Promise.resolve(new Blob(publicKeyEntry.keyDer));
    else
      return Promise.reject(new SecurityException(new Error
        ("IndexedDbIdentityStorage.getKeyPromise: The key does not exist")));
  });
};

/**
 * Check if the specified certificate already exists.
 * @param {Name} certificateName The name of the certificate.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which returns true if the certificate exists.
 */
IndexedDbIdentityStorage.prototype.doesCertificateExistPromise = function
  (certificateName, useSync)
{
  if (useSync)
    return Promise.reject(new SecurityException(new Error
      ("IndexedDbIdentityStorage.doesCertificateExistPromise is only supported for async")));

  return this.database.certificate.where("certificateNameUri").equals
    (certificateName.toUri())
  .count()
  .then(function(count) {
    return Promise.resolve(count > 0);
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
IndexedDbIdentityStorage.prototype.addCertificatePromise = function
  (certificate, useSync)
{
  if (useSync)
    return Promise.reject(new SecurityException(new Error
      ("IndexedDbIdentityStorage.addCertificatePromise is only supported for async")));

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

    // Insert the certificate.
    // wireEncode returns the cached encoding if available.
    return thisStorage.database.certificate.put
      ({ certificateNameUri: certificateName.toUri(),
         encoding: certificate.wireEncode().buf() });
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
IndexedDbIdentityStorage.prototype.getCertificatePromise = function
  (certificateName, useSync)
{
  if (useSync)
    return Promise.reject(new SecurityException(new Error
      ("IndexedDbIdentityStorage.getCertificatePromise is only supported for async")));

  return this.database.certificate.get(certificateName.toUri())
  .then(function(certificateEntry) {
    if (certificateEntry) {
      var certificate = new IdentityCertificate();
      try {
        certificate.wireDecode(certificateEntry.encoding);
      } catch (ex) {
        return Promise.reject(new SecurityException(new Error
          ("IndexedDbIdentityStorage.getCertificatePromise: The certificate cannot be decoded")));
      }
      return Promise.resolve(certificate);
    }
    else
      return Promise.reject(new SecurityException(new Error
        ("IndexedDbIdentityStorage.getCertificatePromise: The certificate does not exist")));
  });
};

/*****************************************
 *           Get/Set Default             *
 *****************************************/

/**
 * Get the default identity.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which returns the Name of default identity,
 * or a promise rejected with SecurityException if the default identity is not
 * set.
 */
IndexedDbIdentityStorage.prototype.getDefaultIdentityPromise = function(useSync)
{
  return this.database.globals.get("defaultIdentityUri")
  .then(function(defaultIdentityEntry) {
    if (defaultIdentityEntry)
      return Promise.resolve(new Name(defaultIdentityEntry.value));
    else
      throw new SecurityException(new Error
        ("IndexedDbIdentityStorage.getDefaultIdentity: The default identity is not defined"));
  });
};

/**
 * Get the default key name for the specified identity.
 * @param {Name} identityName The identity name.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which returns the default key Name, or a
 * promise rejected with SecurityException if the default key name for the
 * identity is not set.
 */
IndexedDbIdentityStorage.prototype.getDefaultKeyNameForIdentityPromise = function
  (identityName, useSync)
{
  if (useSync)
    return Promise.reject(new SecurityException(new Error
      ("IndexedDbIdentityStorage.getDefaultKeyNameForIdentityPromise is only supported for async")));

  return this.database.identity.get(identityName.toUri())
  .then(function(identityEntry) {
    if (identityEntry) {
      if (identityEntry.defaultKeyUri != null)
        return Promise.resolve(new Name(identityEntry.defaultKeyUri));
      else
        throw new SecurityException(new Error("No default key set."));
    }
    else
      throw new SecurityException(new Error("Identity not found."));
  });
};

/**
 * Get the default certificate name for the specified key.
 * @param {Name} keyName The key name.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which returns the default certificate Name,
 * or a promise rejected with SecurityException if the default certificate name
 * for the key name is not set.
 */
IndexedDbIdentityStorage.prototype.getDefaultCertificateNameForKeyPromise = function
  (keyName, useSync)
{
  if (useSync)
    return Promise.reject(new SecurityException(new Error
      ("IndexedDbIdentityStorage.getDefaultCertificateNameForKeyPromise is only supported for async")));

  return this.database.publicKey.get(keyName.toUri())
  .then(function(publicKeyEntry) {
    if (publicKeyEntry) {
      if (publicKeyEntry.defaultCertificateUri != null)
        return Promise.resolve(new Name(publicKeyEntry.defaultCertificateUri));
      else
        throw new SecurityException(new Error("No default certificate set."));
    }
    else
      throw new SecurityException(new Error("Key not found."));
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
IndexedDbIdentityStorage.prototype.getAllIdentitiesPromise = function
  (nameList, isDefault, useSync)
{
  if (useSync)
    return Promise.reject(new SecurityException(new Error
      ("IndexedDbIdentityStorage.getAllIdentitiesPromise is only supported for async")));

  var defaultIdentityName = null;
  var thisStorage = this;
  return this.getDefaultIdentityPromise()
  .then(function(localDefaultIdentityName) {
    defaultIdentityName = localDefaultIdentityName;
    return SyncPromise.resolve();
  }, function(err) {
    // The default identity name was not found.
    return SyncPromise.resolve();
  })
  .then(function() {
    return thisStorage.database.identity.each(function(identityEntry) {
      var identityName = new Name(identityEntry.identityNameUri);
      var identityNameIsDefault =
        (defaultIdentityName !== null && identityName.equals(defaultIdentityName));
      if (isDefault && identityNameIsDefault)
        nameList.push(identityName);
      else if (!isDefault && !identityNameIsDefault)
        nameList.push(identityName);
    });
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
IndexedDbIdentityStorage.prototype.getAllKeyNamesOfIdentityPromise = function
  (identityName, nameList, isDefault, useSync)
{
  if (useSync)
    return Promise.reject(new SecurityException(new Error
      ("IndexedDbIdentityStorage.getAllKeyNamesOfIdentityPromise is only supported for async")));

  var defaultKeyName = null;
  var thisStorage = this;
  return this.getDefaultKeyNameForIdentityPromise(identityName)
  .then(function(localDefaultKeyName) {
    defaultKeyName = localDefaultKeyName;
    return SyncPromise.resolve();
  }, function(err) {
    // The default key name was not found.
    return SyncPromise.resolve();
  })
  .then(function() {
    // Iterate through each publicKey a to find ones that match identityName.
    // This is a little inefficient, but we don't expect the in-browser
    // database to be very big, we don't expect to use this function often (for
    // deleting an identity), and this is simpler than complicating the database
    // schema to store the identityName with each publicKey.
    return thisStorage.database.publicKey.each(function(publicKeyEntry) {
      var keyName = new Name(publicKeyEntry.keyNameUri);
      var keyIdentityName = keyName.getPrefix(-1);

      if (keyIdentityName.equals(identityName)) {
        var keyNameIsDefault =
          (defaultKeyName !== null && keyName.equals(defaultKeyName));
        if (isDefault && keyNameIsDefault)
          nameList.push(keyName);
        else if (!isDefault && !keyNameIsDefault)
          nameList.push(keyName);
      }
    });
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
IndexedDbIdentityStorage.prototype.getAllCertificateNamesOfKeyPromise = function
  (keyName, nameList, isDefault, useSync)
{
  if (useSync)
    return Promise.reject(new SecurityException(new Error
      ("IndexedDbIdentityStorage.getAllCertificateNamesOfKeyPromise is only supported for async")));

  var defaultCertificateName = null;
  var thisStorage = this;
  return this.getDefaultCertificateNameForKeyPromise(keyName)
  .then(function(localDefaultCertificateName) {
    defaultCertificateName = localDefaultCertificateName;
    return SyncPromise.resolve();
  }, function(err) {
    // The default certificate name was not found.
    return SyncPromise.resolve();
  })
  .then(function() {
    // Iterate through each certificate record a to find ones that match keyName.
    // This is a little inefficient, but we don't expect the in-browser
    // database to be very big, we don't expect to use this function often (for
    // deleting an identity), and this is simpler than complicating the database
    // schema to store the keyName with each certificate record.
    return thisStorage.database.certificate.each(function(certificateEntry) {
      var certificateName = new Name(certificateEntry.certificateNameUri);
      var certificateKeyName = IdentityCertificate.certificateNameToPublicKeyName
        (certificateName);

      if (certificateKeyName.equals(keyName)) {
        var certificateNameIsDefault =
          (defaultCertificateName !== null &&
           certificateName.equals(defaultCertificateName));
        if (isDefault && certificateNameIsDefault)
          nameList.push(certificateName);
        else if (!isDefault && !certificateNameIsDefault)
          nameList.push(certificateName);
      }
    });
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
IndexedDbIdentityStorage.prototype.setDefaultIdentityPromise = function
  (identityName, useSync)
{
  if (useSync)
    return Promise.reject(new SecurityException(new Error
      ("IndexedDbIdentityStorage.setDefaultIdentityPromise is only supported for async")));

  var thisStorage = this;
  return this.doesIdentityExistPromise(identityName)
  .then(function(exists) {
    if (exists)
      return thisStorage.database.globals.put
        ({ key: "defaultIdentityUri", value: identityName.toUri() });
    else
      // The identity doesn't exist, so clear the default.
      return thisStorage.database.globals.delete("defaultIdentityUri");
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
 * @return {Promise} A promise which fulfills when the default key name is
 * set.
 */
IndexedDbIdentityStorage.prototype.setDefaultKeyNameForIdentityPromise = function
  (keyName, identityNameCheck, useSync)
{
  useSync = (typeof identityNameCheck === "boolean") ? identityNameCheck : useSync;
  identityNameCheck = (identityNameCheck instanceof Name) ? identityNameCheck : null;

  if (useSync)
    return Promise.reject(new SecurityException(new Error
      ("IndexedDbIdentityStorage.setDefaultKeyNameForIdentityPromise is only supported for async")));

  var identityName = keyName.getPrefix(-1);

  if (identityNameCheck != null && identityNameCheck.size() > 0 &&
      !identityNameCheck.equals(identityName))
    return Promise.reject(new SecurityException(new Error
      ("The specified identity name does not match the key name")));

  // update does nothing if the identityName doesn't exist.
  return this.database.identity.update
    (identityName.toUri(), { defaultKeyUri: keyName.toUri() });
};

/**
 * Set the default key name for the specified identity.
 * @param {Name} keyName The key name.
 * @param {Name} certificateName The certificate name.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which fulfills when the default certificate
 * name is set.
 */
IndexedDbIdentityStorage.prototype.setDefaultCertificateNameForKeyPromise = function
  (keyName, certificateName, useSync)
{
  if (useSync)
    return Promise.reject(new SecurityException(new Error
      ("IndexedDbIdentityStorage.setDefaultCertificateNameForKeyPromise is only supported for async")));

  // update does nothing if the keyName doesn't exist.
  return this.database.publicKey.update
    (keyName.toUri(), { defaultCertificateUri: certificateName.toUri() });
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
IndexedDbIdentityStorage.prototype.deleteCertificateInfoPromise = function
  (certificateName, useSync)
{
  if (useSync)
    return Promise.reject(new SecurityException(new Error
      ("IndexedDbIdentityStorage.deleteCertificateInfoPromise is only supported for async")));

  if (certificateName.size() === 0)
    return Promise.resolve();

  return this.database.certificate.delete(certificateName.toUri());
};

/**
 * Delete a public key and related certificates.
 * @param {Name} keyName The key name.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which fulfills when the public key info is
 * deleted.
 */
IndexedDbIdentityStorage.prototype.deletePublicKeyInfoPromise = function
  (keyName, useSync)
{
  if (useSync)
    return Promise.reject(new SecurityException(new Error
      ("IndexedDbIdentityStorage.deletePublicKeyInfoPromise is only supported for async")));

  if (keyName.size() === 0)
    return Promise.resolve();

  var thisStorage = this;
  return this.database.publicKey.delete(keyName.toUri())
  .then(function() {
    // Iterate through each certificate to find ones that match keyName. This is
    // a little inefficient, but we don't expect the in-browswer database to be
    // very big, we don't expect to delete often, and this is simpler than
    // complicating the database schema to store the keyName with each certificate.
    return thisStorage.database.certificate.each(function(certificateEntry) {
      if (IdentityCertificate.certificateNameToPublicKeyName
          (new Name(certificateEntry.certificateNameUri)).equals(keyName))
        thisStorage.database.certificate.delete
          (certificateEntry.certificateNameUri);
    });
  });
};

/**
 * Delete an identity and related public keys and certificates.
 * @param {Name} identityName The identity name.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which fulfills when the identity info is
 * deleted.
 */
IndexedDbIdentityStorage.prototype.deleteIdentityInfoPromise = function
  (identityName, useSync)
{
  if (useSync)
    return Promise.reject(new SecurityException(new Error
      ("IndexedDbIdentityStorage.deleteIdentityInfoPromise is only supported for async")));

  var thisStorage = this;
  return this.database.identity.delete(identityName.toUri())
  // Iterate through each publicKey and certificate to find ones that match
  // identityName. This is a little inefficient, but we don't expect the
  // in-browswer database to be very big, we don't expect to delete often, and
  // this is simpler than complicating the database schema to store the
  // identityName with each publicKey and certificate.
  .then(function() {
    return thisStorage.database.publicKey.each(function(publicKeyEntry) {
      var keyIdentityName = new Name(publicKeyEntry.keyNameUri).getPrefix(-1);
      if (keyIdentityName.equals(identityName))
        thisStorage.database.publicKey.delete(publicKeyEntry.keyNameUri);
    });
  })
  .then(function() {
    return thisStorage.database.certificate.each(function(certificateEntry) {
      var certificateKeyName = IdentityCertificate.certificateNameToPublicKeyName
        (new Name(certificateEntry.certificateNameUri));
      var certificateIdentityName = certificateKeyName.getPrefix(-1);
      if (certificateIdentityName.equals(identityName))
        thisStorage.database.certificate.delete
          (certificateEntry.certificateNameUri);
    });
  });
};
