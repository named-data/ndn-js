/**
 * Copyright (C) 2018 Regents of the University of California.
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

/**
 * PibIndexedDb extends PibImpl and is used by the Pib class to store the
 * contents of the PIB using the browser's IndexedDB service.
 * @constructor
 */
var PibIndexedDb = function PibIndexedDb()
{
  // Call the base constructor.
  PibImpl.call(this);

  this.database = new Dexie("pib");
  this.database.version(1).stores({
    // A table for global values. It currently only has tpmLocator and
    // defaultIdentityUri.
    // "key" is the key like "tpmLocator" // string
    // "value" is the value. For "defaultIdentityUri" the value is the
    //         default identity name URI, or absent if not defined. // string
    globals: "key",

    // "identityNameUri" is the identity name URI          // string
    // "defaultKeyUri" is the default key name URI or null // string
    identities: "identityNameUri",

    // "keyNameUri" is the key name URI                             // string
    // "keyDer" is the public key DER                               // Uint8Array
    // "defaultCertificateUri" is the default cert name URI or null // string
    keys: "keyNameUri",

    // "certificateNameUri" is the certificate name URI // string
    // "encoding" is the certificate wire encoding      // Uint8Array
    certificates: "certificateNameUri"
  });
  this.database.open();
};

PibIndexedDb.prototype = new PibImpl();
PibIndexedDb.prototype.name = "PibIndexedDb";

exports.PibIndexedDb = PibIndexedDb;

PibIndexedDb.getScheme = function() { return "pib-indexeddb"; }

// TpmLocator management.

/**
 * Set the corresponding TPM information to tpmLocator. This method does not
 * reset the contents of the PIB.
 * @param {string} tpmLocator The TPM locator string.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which fulfills when the TPM locator is set.
 */
PibIndexedDb.prototype.setTpmLocatorPromise = function(tpmLocator, useSync)
{
  if (useSync)
    return Promise.reject(new PibImpl.Error(new Error
      ("PibIndexedDb.setTpmLocatorPromise is only supported for async")));

  return this.database.globals.put({ key: "tpmLocator", value: tpmLocator });
};

/**
 * Get the TPM Locator.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which returns the TPM locator string.
 */
PibIndexedDb.prototype.getTpmLocatorPromise = function(useSync)
{
  if (useSync)
    return Promise.reject(new PibImpl.Error(new Error
      ("PibIndexedDb.getTpmLocatorPromise is only supported for async")));

  return this.database.globals.get("tpmLocator")
  .then(function(entry) {
    if (entry)
      return Promise.resolve(entry.value);
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
PibIndexedDb.prototype.hasIdentityPromise = function(identityName, useSync)
{
  if (useSync)
    return Promise.reject(new PibImpl.Error(new Error
      ("PibIndexedDb.hasIdentityPromise is only supported for async")));

  return this.database.identities.where("identityNameUri").equals
    (identityName.toUri())
  .count()
  .then(function(count) {
    return Promise.resolve(count > 0);
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
PibIndexedDb.prototype.addIdentityPromise = function(identityName, useSync)
{
  if (useSync)
    return Promise.reject(new PibImpl.Error(new Error
      ("PibIndexedDb.addIdentityPromise is only supported for async")));

  var thisPib = this;
  return this.hasIdentityPromise(identityName)
  .then(function(hasIdentity) {
    if (!hasIdentity)
      return thisPib.database.identities.put
        ({ identityNameUri: identityName.toUri(), defaultKeyUri: null });
    else
      return Promise.resolve();
  })
  .then(function() {
    return thisPib.database.globals.get("defaultIdentityUri");
  })
  .then(function(entry) {
    if (!entry)
      // No default identity, so make this the default.
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
PibIndexedDb.prototype.removeIdentityPromise = function(identityName, useSync)
{
  if (useSync)
    return Promise.reject(new PibImpl.Error(new Error
      ("PibIndexedDb.removeIdentityPromise is only supported for async")));

  var identityNameUri = identityName.toUri();
  var thisPib = this;

  // We don't use triggers, so manually delete from keys and certificates.
  // Iterate through each key and certificate to find ones that match
  // identityName. This is a little inefficient, but we don't expect the
  // in-browswer database to be very big, we don't expect to delete often, and
  // this is simpler than complicating the database schema to store the
  // identityName with each key and certificate.
  return this.database.certificates.each(function(entry) {
    if (CertificateV2.extractIdentityFromCertName
        (new Name(entry.certificateNameUri)).equals(identityName))
      thisPib.database.certificates.delete(entry.certificateNameUri);
  })
  .then(function() {
    return thisPib.database.keys.each(function(entry) {
      if (PibKey.extractIdentityFromKeyName
          (new Name(entry.keyNameUri)).equals(identityName))
        thisPib.database.keys.delete(entry.keyNameUri);
    });
  })
  .then(function() {
    return thisPib.database.identities.delete(identityNameUri);
  })
  .then(function() {
    // Clear the default identity, if it is this identity.
    return thisPib.database.globals.get("defaultIdentityUri")
  })
  .then(function(entry) {
    if (entry && entry.value == identityNameUri)
      return thisPib.database.globals.delete("defaultIdentityUri");
    else
      return Promise.resolve();
  });
};

/**
 * Erase all certificates, keys, and identities.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which fulfills when the identities are cleared.
 */
PibIndexedDb.prototype.clearIdentitiesPromise = function(useSync)
{
  if (useSync)
    return Promise.reject(new PibImpl.Error(new Error
      ("PibIndexedDb.clearIdentitiesPromise is only supported for async")));

  var thisPib = this;
  return this.database.globals.delete("defaultIdentityUri")
  // We don't use triggers, so manually delete from keys and certificates.
  .then(function() {
    return thisPib.database.certificates.clear();
  })
  .then(function() {
    return thisPib.database.keys.clear();
  })
  .then(function() {
    return thisPib.database.identities.clear();
  });
};

/**
 * Get the names of all the identities.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which returns a fresh set of identity names
 * as an array of Name. The Name objects are fresh copies.
 */
PibIndexedDb.prototype.getIdentitiesPromise = function(useSync)
{
  if (useSync)
    return Promise.reject(new PibImpl.Error(new Error
      ("PibIndexedDb.getIdentitiesPromise is only supported for async")));

  var identities = [];

  return this.database.identities.each(function(entry) {
    identities.push(new Name(entry.identityNameUri));
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
PibIndexedDb.prototype.setDefaultIdentityPromise = function(identityName, useSync)
{
  if (useSync)
    return Promise.reject(new PibImpl.Error(new Error
      ("PibIndexedDb.setDefaultIdentityPromise is only supported for async")));

  var thisPib = this;
  return this.hasIdentityPromise(identityName)
  .then(function(hasIdentity) {
    if (!hasIdentity)
      // Use the same command from addIdentityPromise, but don't call it because
      // it again calls this function.
      return thisPib.database.identities.put
        ({ identityNameUri: identityName.toUri(), defaultKeyUri: null });
    else
      return Promise.resolve();
  })
  .then(function() {
    return thisPib.database.globals.put
      ({ key: "defaultIdentityUri", value: identityName.toUri() });
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
PibIndexedDb.prototype.getDefaultIdentityPromise = function(useSync)
{
  if (useSync)
    return Promise.reject(new PibImpl.Error(new Error
      ("PibIndexedDb.getDefaultIdentityPromise is only supported for async")));

  return this.database.globals.get("defaultIdentityUri")
  .then(function(entry) {
    if (entry)
      return Promise.resolve(new Name(entry.value));
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
PibIndexedDb.prototype.hasKeyPromise = function(keyName, useSync)
{
  if (useSync)
    return Promise.reject(new PibImpl.Error(new Error
      ("PibIndexedDb.hasKeyPromise is only supported for async")));

  return this.database.keys.where("keyNameUri").equals(keyName.toUri())
  .count()
  .then(function(count) {
    return Promise.resolve(count > 0);
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
PibIndexedDb.prototype.addKeyPromise = function
  (identityName, keyName, key, useSync)
{
  if (useSync)
    return Promise.reject(new PibImpl.Error(new Error
      ("PibIndexedDb.addKeyPromise is only supported for async")));

  var thisPib = this;

  // Ensure the identity exists.
  return this.addIdentityPromise(identityName)
  .then(function() {
    return thisPib.hasKeyPromise(keyName);
  })
  .then(function(hasKey) {
    if (!hasKey)
      return thisPib.database.keys.put
        ({ keyNameUri: keyName.toUri(), keyDer: key,
           defaultCertificateUri: null });
    else
      // Update the keyDer and keep the defaultCertificateUri.
      return thisPib.database.keys.update(keyName.toUri(), { keyDer: key });
  })
  .then(function() {
    // Check for the default key.
    return thisPib.database.identities.get(identityName.toUri());
  })
  .then(function(entry) {
    if (entry && entry.defaultKeyUri != null)
      // Make sure the default key still exists, since removeKey doesn't clear it.
      return thisPib.hasKeyPromise(new Name(entry.defaultKeyUri));
    else
      return Promise.resolve(false);
  })
  .then(function(hasDefaultKey) {
    if (hasDefaultKey)
      // We already have a default key, so do nothing.
      return Promise.resolve();
    else
      return thisPib.setDefaultKeyOfIdentityPromise(identityName, keyName);
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
PibIndexedDb.prototype.removeKeyPromise = function(keyName, useSync)
{
  if (useSync)
    return Promise.reject(new PibImpl.Error(new Error
      ("PibIndexedDb.removeKeyPromise is only supported for async")));

  var thisPib = this;

  // We don't use triggers, so manually delete from certificates.
  // Iterate through each certificate to find ones that match keyName. This is
  // a little inefficient, but we don't expect the in-browswer database to be
  // very big, we don't expect to delete often, and this is simpler than
  // complicating the database schema to store the keyName with each certificate.
  return this.database.certificates.each(function(entry) {
    if (CertificateV2.extractKeyNameFromCertName
        (new Name(entry.certificateNameUri)).equals(keyName))
      thisPib.database.certificates.delete(entry.certificateNameUri);
  })
  .then(function() {
    return thisPib.database.keys.delete(keyName.toUri());
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
PibIndexedDb.prototype.getKeyBitsPromise = function(keyName, useSync)
{
  if (useSync)
    return Promise.reject(new PibImpl.Error(new Error
      ("PibIndexedDb.getKeyBitsPromise is only supported for async")));

  return this.database.keys.get(keyName.toUri())
  .then(function(entry) {
    if (entry)
      return Promise.resolve(new Blob(entry.keyDer));
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
PibIndexedDb.prototype.getKeysOfIdentityPromise = function(identityName, useSync)
{
  if (useSync)
    return Promise.reject(new PibImpl.Error(new Error
      ("PibIndexedDb.getKeysOfIdentityPromise is only supported for async")));

  var keyNames = [];

  // Iterate through each key to find ones that match identityName.
  // This is a little inefficient, but we don't expect the in-browser
  // database to be very big, and this is simpler than complicating the database
  // schema to store the identityName with each key.
  return this.database.keys.each(function(entry) {
    var keyName = new Name(entry.keyNameUri);

    if (PibKey.extractIdentityFromKeyName(keyName).equals(identityName))
      keyNames.push(keyName);
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
PibIndexedDb.prototype.setDefaultKeyOfIdentityPromise = function
  (identityName, keyName, useSync)
{
  if (useSync)
    return Promise.reject(new PibImpl.Error(new Error
      ("PibIndexedDb.setDefaultKeyOfIdentityPromise is only supported for async")));

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
    // update does nothing if the identityName doesn't exist.
    return thisPib.database.identities.update
      (identityName.toUri(), { defaultKeyUri: keyName.toUri() });
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
PibIndexedDb.prototype.getDefaultKeyOfIdentityPromise = function
  (identityName, useSync)
{
  if (useSync)
    return Promise.reject(new PibImpl.Error(new Error
      ("PibIndexedDb.getDefaultKeyOfIdentityPromise is only supported for async")));

  var thisPib = this;

  return this.database.identities.get(identityName.toUri())
  .then(function(entry) {
    if (entry) {
      if (entry.defaultKeyUri != null) {
        // Make sure the key still exists.
        var keyName = new Name(entry.defaultKeyUri);

        return thisPib.hasKeyPromise(keyName)
        .then(function(hasKey) {
          if (hasKey)
            return Promise.resolve(keyName);
          else
            return Promise.reject(new Pib.Error(new Error
              ("No default key for identity `" + identityName.toUri() + "`")));
        });
      }
      else
        return Promise.reject(new Pib.Error(new Error
          ("No default key for identity `" + identityName.toUri() + "`")));
    }
    else
      return Promise.reject(new Pib.Error(new Error
        ("Identity `" + identityName.toUri() + "` does not exist")));
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
PibIndexedDb.prototype.hasCertificatePromise = function(certificateName, useSync)
{
  if (useSync)
    return Promise.reject(new PibImpl.Error(new Error
      ("PibIndexedDb.hasCertificatePromise is only supported for async")));

  return this.database.certificates.where("certificateNameUri").equals
    (certificateName.toUri())
  .count()
  .then(function(count) {
    return Promise.resolve(count > 0);
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
PibIndexedDb.prototype.addCertificatePromise = function(certificate, useSync)
{
  if (useSync)
    return Promise.reject(new PibImpl.Error(new Error
      ("PibIndexedDb.addCertificatePromise is only supported for async")));

  var keyName = certificate.getKeyName();
  var keyNameUri = keyName.toUri();
  var thisPib = this;

  // Ensure the key exists.
  var content = certificate.getContent();
  return this.addKeyPromise(certificate.getIdentity(), keyName, content.buf())
  .then(function() {
    // Insert the certificate.
    // wireEncode returns the cached encoding if available.
    return thisPib.database.certificates.put
      ({ certificateNameUri: certificate.getName().toUri(),
         encoding: certificate.wireEncode().buf() });
  })
  .then(function() {
    // Check for the default certificate.
    return thisPib.database.keys.get(keyNameUri);
  })
  .then(function(entry) {
    if (entry && entry.defaultCertificateUri != null)
      // Make sure the default certificate still exists, since removeCertiticate
      // doesn't clear it..
      return thisPib.hasCertificatePromise(new Name(entry.defaultCertificateUri));
    else
      return Promise.resolve(false);
  })
  .then(function(hasDefaultCertificate) {
    if (hasDefaultCertificate)
      // We already have a default certificate, so do nothing.
      return Promise.resolve();
    else
      return thisPib.setDefaultCertificateOfKeyPromise
        (keyName, certificate.getName());
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
PibIndexedDb.prototype.removeCertificatePromise = function
  (certificateName, useSync)
{
  if (useSync)
    return Promise.reject(new PibImpl.Error(new Error
      ("PibIndexedDb.removeCertificatePromise is only supported for async")));

  return this.database.certificates.delete(certificateName.toUri());
};

/**
 * Get the certificate with name certificateName.
 * @param {Name} certificateName The name of the certificate.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which returns the CertificateV2, or a promise
 * rejected with Pib.Error if the certificate does not exist.
 */
PibIndexedDb.prototype.getCertificatePromise = function(certificateName, useSync)
{
  if (useSync)
    return Promise.reject(new PibImpl.Error(new Error
      ("PibIndexedDb.getCertificatePromise is only supported for async")));

  return this.database.certificates.get(certificateName.toUri())
  .then(function(entry) {
    if (entry) {
      var certificate = new CertificateV2();
      certificate.wireDecode(entry.encoding);
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
PibIndexedDb.prototype.getCertificatesOfKeyPromise = function(keyName, useSync)
{
  if (useSync)
    return Promise.reject(new PibImpl.Error(new Error
      ("PibIndexedDb.getCertificatesOfKeyPromise is only supported for async")));

  var certificateNames = [];

  // Iterate through each certificate to find ones that match keyName.
  // This is a little inefficient, but we don't expect the in-browser
  // database to be very big, and this is simpler than complicating the database
  // schema to store the keyName with each certificate.
  return this.database.certificates.each(function(entry) {
    var certificateName = new Name(entry.certificateNameUri);

    if (CertificateV2.extractKeyNameFromCertName(certificateName).equals(keyName))
      certificateNames.push(certificateName);
  })
  .then(function() {
    return Promise.resolve(certificateNames);
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
PibIndexedDb.prototype.setDefaultCertificateOfKeyPromise = function
  (keyName, certificateName, useSync)
{
  if (useSync)
    return Promise.reject(new PibImpl.Error(new Error
      ("PibIndexedDb.setDefaultCertificateOfKeyPromise is only supported for async")));

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
     // update does nothing if the keyName doesn't exist.
    return thisPib.database.keys.update
      (keyName.toUri(), { defaultCertificateUri: certificateName.toUri() });
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
PibIndexedDb.prototype.getDefaultCertificateOfKeyPromise = function
  (keyName, useSync)
{
  if (useSync)
    return Promise.reject(new PibImpl.Error(new Error
      ("PibIndexedDb.getDefaultCertificateOfKeyPromise is only supported for async")));

  var thisPib = this;

  return this.database.keys.get(keyName.toUri())
  .then(function(entry) {
    if (entry && entry.defaultCertificateUri != null)
      return thisPib.getCertificatePromise(new Name(entry.defaultCertificateUri));
    else
      return Promise.reject(new Pib.Error(new Error
        ("No default certificate for key `" + keyName.toUri() + "`")));
  });
};
