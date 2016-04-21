/**
 * Copyright (C) 2015-2016 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt src/consumer https://github.com/named-data/ndn-group-encrypt
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
var Blob = require('../util/blob.js').Blob; /** @ignore */
var Name = require('../name.js').Name; /** @ignore */
var Interest = require('../interest.js').Interest; /** @ignore */
var EncryptedContent = require('./encrypted-content.js').EncryptedContent; /** @ignore */
var EncryptError = require('./encrypt-error.js').EncryptError; /** @ignore */
var EncryptParams = require('./algo/encrypt-params.js').EncryptParams; /** @ignore */
var EncryptAlgorithmType = require('./algo/encrypt-params.js').EncryptAlgorithmType; /** @ignore */
var RsaAlgorithm = require('./algo/rsa-algorithm.js').RsaAlgorithm; /** @ignore */
var AesAlgorithm = require('./algo/aes-algorithm.js').AesAlgorithm; /** @ignore */
var Encryptor = require('./algo/encryptor.js').Encryptor; /** @ignore */
var SyncPromise = require('../util/sync-promise.js').SyncPromise; /** @ignore */
var NdnCommon = require('../util/ndn-common.js').NdnCommon;

/**
 * A Consumer manages fetched group keys used to decrypt a data packet in the
 * group-based encryption protocol.
 * Create a Consumer to use the given ConsumerDb, Face and other values.
 * @param {Face} face The face used for data packet and key fetching.
 * @param {KeyChain} keyChain The keyChain used to verify data packets.
 * @param {Name} groupName The reading group name that the consumer belongs to.
 * This makes a copy of the Name.
 * @param {Name} consumerName The identity of the consumer. This makes a copy of
 * the Name.
 * @param {ConsumerDb} database The ConsumerDb database for storing decryption
 * keys.
 * @note This class is an experimental feature. The API may change.
 * @constructor
 */
var Consumer = function Consumer
  (face, keyChain, groupName, consumerName, database)
{
  this.database_ = database;
  this.keyChain_ = keyChain;
  this.face_ = face;
  this.groupName_ = new Name(groupName);
  this.consumerName_ = new Name(consumerName);

  // The map key is the C-KEY name URI string. The value is the encoded key Blob.
  // (Use a string because we can't use the Name object as the key in JavaScript.
  this.cKeyMap_ = {};
  // The map key is the D-KEY name URI string. The value is the encoded key Blob.
  this.dKeyMap_ = {};
};

exports.Consumer = Consumer;

/**
 * Express an Interest to fetch the content packet with contentName, and
 * decrypt it, fetching keys as needed.
 * @param {Name} contentName The name of the content packet.
 * @param {function} onConsumeComplete When the content packet is fetched and
 * decrypted, this calls onConsumeComplete(contentData, result) where
 * contentData is the fetched Data packet and result is the decrypted plain
 * text Blob.
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onError This calls onError(errorCode, message) for an error,
 * where errorCode is an error code from EncryptError.ErrorCode.
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 */
Consumer.prototype.consume = function(contentName, onConsumeComplete, onError)
{
  var interest = new Interest(contentName);

  // Prepare the callback functions.
  var thisConsumer = this;
  var onData = function(contentInterest, contentData) {
    // The Interest has no selectors, so assume the library correctly
    // matched with the Data name before calling onData.

    try {
      thisConsumer.keyChain_.verifyData(contentData, function(validData) {
        // Decrypt the content.
        thisConsumer.decryptContent_(validData, function(plainText) {
          try {
            onConsumeComplete(contentData, plainText);
          } catch (ex) {
            console.log("Error in onConsumeComplete: " + NdnCommon.getErrorWithStackTrace(ex));
          }
        }, onError);
      }, function(d) {
        try {
          onError(EncryptError.ErrorCode.Validation, "verifyData failed");
        } catch (ex) {
          console.log("Error in onError: " + NdnCommon.getErrorWithStackTrace(ex));
        }
      });
    } catch (ex) {
      Consumer.Error.callOnError(onError, ex, "verifyData error: ");
    }
  };

  var onTimeout = function(contentInterest) {
    // We should re-try at least once.
    try {
      thisConsumer.face_.expressInterest
        (interest, onData, function(contentInterest) {
        try {
          onError(EncryptError.ErrorCode.Timeout, interest.getName().toUri());
        } catch (ex) {
          console.log("Error in onError: " + NdnCommon.getErrorWithStackTrace(ex));
        }
       });
    } catch (ex) {
      Consumer.Error.callOnError(onError, ex, "expressInterest error: ");
    }
  };

  // Express the Interest.
  try {
    this.face_.expressInterest(interest, onData, onTimeout);
  } catch (ex) {
    Consumer.Error.callOnError(onError, ex, "expressInterest error: ");
  }
};

/**
 * Set the group name.
 * @param {Name} groupName The reading group name that the consumer belongs to.
 * This makes a copy of the Name.
 */
Consumer.prototype.setGroup = function(groupName)
{
  this.groupName_ = new Name(groupName);
};

/**
 * Add a new decryption key with keyName and keyBlob to the database.
 * @param {Name} keyName The key name.
 * @param {Blob} keyBlob The encoded key.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that fulfills when the key is added,
 * or that is rejected with Error if the consumer name is not a prefix of the
 * key name, or ConsumerDb.Error if a key with the same keyName already exists,
 * or other database error.
 */
Consumer.prototype.addDecryptionKeyPromise = function(keyName, keyBlob, useSync)
{
  if (!(this.consumerName_.match(keyName)))
    return SyncPromise.reject(new Error
      ("addDecryptionKey: The consumer name must be a prefix of the key name"));

  return this.database_.addKeyPromise(keyName, keyBlob, useSync);
};

/**
 * Add a new decryption key with keyName and keyBlob to the database.
 * @param {Name} keyName The key name.
 * @param {Blob} keyBlob The encoded key.
 * @param {function} onComplete (optional) This calls onComplete() when the key
 * is added. (Some database libraries only use a callback, so onComplete is
 * required to use these.)
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * where exception is Error if the consumer name is not a prefix of the key
 * name, or ConsumerDb.Error if a key with the same keyName already exists,
 * or other database error. If onComplete is defined but onError is undefined,
 * then this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 */
Consumer.prototype.addDecryptionKey = function
  (keyName, keyBlob, onComplete, onError)
{
  return SyncPromise.complete(onComplete, onError,
    this.addDecryptionKeyPromise(keyName, keyBlob, !onComplete));
};

/**
 * Consume.Error is used internally from promised-based methods to reject with
 * an error object that has the errorCode and message returned through the
 * onError callback.
 * @param {number} errorCode An error code from EncryptError.ErrorCode.
 * @param {string} message The error message.
 */
Consumer.Error = function ConsumerError(errorCode, message)
{
  this.errorCode = errorCode;
  this.message = message;
};

/**
 * If exception is a ConsumerError, then call onError with the errorCode and
 * message, otherwise call onError with ErrorCode.General.
 */
Consumer.Error.callOnError = function(onError, exception, messagePrefix)
{
  if (!messagePrefix)
    messagePrefix = "";

  if (exception instanceof Consumer.Error) {
    try {
      onError(exception.errorCode, exception.message);
    } catch (ex) {
      console.log("Error in onError: " + NdnCommon.getErrorWithStackTrace(ex));
    }
  }
  else {
    try {
      onError(EncryptError.ErrorCode.General, messagePrefix + exception);
    } catch (ex) {
      console.log("Error in onError: " + NdnCommon.getErrorWithStackTrace(ex));
    }
  }
}

/**
 * Decrypt encryptedContent using keyBits.
 * @param {Blob|EncryptedContent} encryptedContent The EncryptedContent to
 * decrypt, or a Blob which is first decoded as an EncryptedContent.
 * @param {Blob} keyBits The key value.
 * @return {Promise|SyncPromise} A promise that returns the decrypted Blob, or
 * that is rejected with Consumer.Error or other error.
 */
Consumer.decryptPromise_ = function(encryptedContent, keyBits)
{
  return SyncPromise.resolve()
  .then(function() {
    if (typeof encryptedContent == 'object' && encryptedContent instanceof Blob) {
      // Decode as EncryptedContent.
      var encryptedBlob = encryptedContent;
      encryptedContent = new EncryptedContent();
      encryptedContent.wireDecode(encryptedBlob);
    }

    var payload = encryptedContent.getPayload();

    if (encryptedContent.getAlgorithmType() == EncryptAlgorithmType.AesCbc) {
      // Prepare the parameters.
      var decryptParams = new EncryptParams(EncryptAlgorithmType.AesCbc);
      decryptParams.setInitialVector(encryptedContent.getInitialVector());

      // Decrypt the content.
      return AesAlgorithm.decryptPromise(keyBits, payload, decryptParams);
    }
    else if (encryptedContent.getAlgorithmType() == EncryptAlgorithmType.RsaOaep) {
      // Prepare the parameters.
      var decryptParams = new EncryptParams(EncryptAlgorithmType.RsaOaep);

      // Decrypt the content.
      return RsaAlgorithm.decryptPromise(keyBits, payload, decryptParams);
    }
    else
      return SyncPromise.reject(new Consumer.Error
        (EncryptError.ErrorCode.UnsupportedEncryptionScheme,
          "" + encryptedContent.getAlgorithmType()));
  });
};

/**
 * Decrypt encryptedContent using keyBits.
 * @param {Blob|EncryptedContent} encryptedContent The EncryptedContent to
 * decrypt, or a Blob which is first decoded as an EncryptedContent.
 * @param {Blob} keyBits The key value.
 * @param {function} onPlainText When the data packet is decrypted, this calls
 * onPlainText(decryptedBlob) with the decrypted Blob.
 * @param {function} onError This calls onError(errorCode, message) for an error,
 * where errorCode is an error code from EncryptError.ErrorCode.
 */
Consumer.decrypt_ = function(encryptedContent, keyBits, onPlainText, onError)
{
  Consumer.decryptPromise_(encryptedContent, keyBits)
  .then(function(decryptedBlob) {
    onPlainText(decryptedBlob);
  }, function(ex) {
    Consumer.Error.callOnError(onError, ex);
  });
};

/**
 * Decrypt the data packet.
 * @param {Data} data The data packet.
 * @param {function} onPlainText When the data packet is decrypted, this calls
 * onPlainText(decryptedBlob) with the decrypted Blob.
 * @param {function} onError This calls onError(errorCode, message) for an error,
 * where errorCode is an error code from EncryptError.ErrorCode.
 */
Consumer.prototype.decryptContent_ = function(data, onPlainText, onError)
{
  // Get the encrypted content.
  var dataEncryptedContent = new EncryptedContent();
  try {
    dataEncryptedContent.wireDecode(data.getContent());
  } catch (ex) {
    Consumer.Error.callOnError(onError, ex, "Error decoding EncryptedContent: ");
    return;
  }
  var cKeyName = dataEncryptedContent.getKeyLocator().getKeyName();

  // Check if the content key is already in the store.
  var cKey = this.cKeyMap_[cKeyName.toUri()];
  if (cKey)
    this.decrypt_(dataEncryptedContent, cKey, onPlainText, onError);
  else {
    // Retrieve the C-KEY Data from the network.
    var interestName = new Name(cKeyName);
    interestName.append(Encryptor.NAME_COMPONENT_FOR).append(this.groupName_);
    var interest = new Interest(interestName);

    // Prepare the callback functions.
    var thisConsumer = this;
    var onData = function(cKeyInterest, cKeyData) {
      // The Interest has no selectors, so assume the library correctly
      // matched with the Data name before calling onData.

      try {
        thisConsumer.keyChain_.verifyData(cKeyData, function(validCKeyData) {
          thisConsumer.decryptCKey_(validCKeyData, function(cKeyBits) {
            thisConsumer.cKeyMap_[cKeyName.toUri()] = cKeyBits;
            Consumer.decrypt_
              (dataEncryptedContent, cKeyBits, onPlainText, onError);
          }, onError);
        }, function(d) {
          onError(EncryptError.ErrorCode.Validation, "verifyData failed");
        });
      } catch (ex) {
        Consumer.Error.callOnError(onError, ex, "verifyData error: ");
      }
    };

    var onTimeout = function(dKeyInterest) {
      // We should re-try at least once.
      try {
        thisConsumer.face_.expressInterest
          (interest, onData, function(contentInterest) {
          onError(EncryptError.ErrorCode.Timeout, interest.getName().toUri());
         });
      } catch (ex) {
        Consumer.Error.callOnError(onError, ex, "expressInterest error: ");
      }
    };

    // Express the Interest.
    try {
      thisConsumer.face_.expressInterest(interest, onData, onTimeout);
    } catch (ex) {
      Consumer.Error.callOnError(onError, ex, "expressInterest error: ");
    }
  }
};

/**
 * Decrypt cKeyData.
 * @param {Data} cKeyData The C-KEY data packet.
 * @param {function} onPlainText When the data packet is decrypted, this calls
 * onPlainText(decryptedBlob) with the decrypted Blob.
 * @param {function} onError This calls onError(errorCode, message) for an error,
 * where errorCode is an error code from EncryptError.ErrorCode.
 */
Consumer.prototype.decryptCKey_ = function(cKeyData, onPlainText, onError)
{
  // Get the encrypted content.
  var cKeyContent = cKeyData.getContent();
  var cKeyEncryptedContent = new EncryptedContent();
  try {
    cKeyEncryptedContent.wireDecode(cKeyContent);
  } catch (ex) {
    Consumer.Error.callOnError(onError, ex, "Error decoding EncryptedContent: ");
    return;
  }
  var eKeyName = cKeyEncryptedContent.getKeyLocator().getKeyName();
  var dKeyName = eKeyName.getPrefix(-3);
  dKeyName.append(Encryptor.NAME_COMPONENT_D_KEY).append(eKeyName.getSubName(-2));

  // Check if the decryption key is already in the store.
  var dKey = this.dKeyMap_[dKeyName.toUri()];
  if (dKey)
    this.decrypt_(cKeyEncryptedContent, dKey, onPlainText, onError);
  else {
    // Get the D-Key Data.
    var interestName = new Name(dKeyName);
    interestName.append(Encryptor.NAME_COMPONENT_FOR).append(this.consumerName_);
    var interest = new Interest(interestName);

    // Prepare the callback functions.
    var thisConsumer = this;
    var onData = function(dKeyInterest, dKeyData) {
      // The Interest has no selectors, so assume the library correctly
      // matched with the Data name before calling onData.

      try {
        thisConsumer.keyChain_.verifyData(dKeyData, function(validDKeyData) {
          thisConsumer.decryptDKeyPromise_(validDKeyData)
          .then(function(dKeyBits) {
            thisConsumer.dKeyMap_[dKeyName.toUri()] = dKeyBits;
            Consumer.decrypt_
              (cKeyEncryptedContent, dKeyBits, onPlainText, onError);
          }, function(ex) {
            Consumer.Error.callOnError(onError, ex, "decryptDKey error: ");
          });
        }, function(d) {
          onError(EncryptError.ErrorCode.Validation, "verifyData failed");
        });
      } catch (ex) {
        Consumer.Error.callOnError(onError, ex, "verifyData error: ");
      }
    };

    var onTimeout = function(dKeyInterest) {
      // We should re-try at least once.
      try {
        thisConsumer.face_.expressInterest
          (interest, onData, function(contentInterest) {
          onError(EncryptError.ErrorCode.Timeout, interest.getName().toUri());
         });
      } catch (ex) {
        Consumer.Error.callOnError(onError, ex, "expressInterest error: ");
      }
    };

    // Express the Interest.
    try {
      thisConsumer.face_.expressInterest(interest, onData, onTimeout);
    } catch (ex) {
      Consumer.Error.callOnError(onError, ex, "expressInterest error: ");
    }
  }
};

/**
 * Decrypt dKeyData.
 * @param {Data} dKeyData The D-KEY data packet.
 * @return {Promise|SyncPromise} A promise that returns the decrypted Blob, or
 * that is rejected with Consumer.Error or other error.
 */
Consumer.prototype.decryptDKeyPromise_ = function(dKeyData)
{
  var dataContent;
  var encryptedNonce;
  var encryptedPayloadBlob;
  var thisConsumer = this;

  return SyncPromise.resolve()
  .then(function() {
    // Get the encrypted content.
    dataContent = dKeyData.getContent();

    // Process the nonce.
    // dataContent is a sequence of the two EncryptedContent.
    encryptedNonce = new EncryptedContent();
    encryptedNonce.wireDecode(dataContent);
    var consumerKeyName = encryptedNonce.getKeyLocator().getKeyName();

    // Get consumer decryption key.
    return thisConsumer.getDecryptionKeyPromise_(consumerKeyName);
  })
  .then(function(consumerKeyBlob) {
    if (consumerKeyBlob.size() == 0)
      return SyncPromise.reject(new Consumer.Error
        (EncryptError.ErrorCode.NoDecryptKey,
         "The desired consumer decryption key in not in the database"));

    // Process the D-KEY.
    // Use the size of encryptedNonce to find the start of encryptedPayload.
    var encryptedPayloadBuffer = dataContent.buf().slice
      (encryptedNonce.wireEncode().size());
    encryptedPayloadBlob = new Blob(encryptedPayloadBuffer, false);
    if (encryptedPayloadBlob.size() == 0)
      return SyncPromise.reject(new Consumer.Error
        (EncryptError.ErrorCode.InvalidEncryptedFormat,
         "The data packet does not satisfy the D-KEY packet format"));

    // Decrypt the D-KEY.
    return Consumer.decryptPromise_(encryptedNonce, consumerKeyBlob);
  })
  .then(function(nonceKeyBits) {
    return Consumer.decryptPromise_(encryptedPayloadBlob, nonceKeyBits);
  });
};

/**
 * Get the encoded blob of the decryption key with decryptionKeyName from the
 * database.
 * @param {Name} decryptionKeyName The key name.
 * @return {Promise|SyncPromise} A promise that returns a Blob with the encoded
 * key (or an isNull Blob if cannot find the key with decryptionKeyName), or
 * that is rejected with ConsumerDb.Error for a database error.
 */
Consumer.prototype.getDecryptionKeyPromise_ = function(decryptionKeyName)
{
  return this.database_.getKeyPromise(decryptionKeyName);
};
