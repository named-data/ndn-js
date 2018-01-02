/**
 * Copyright (C) 2015-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt src/producer https://github.com/named-data/ndn-group-encrypt
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
var Name = require('../name.js').Name; /** @ignore */
var Interest = require('../interest.js').Interest; /** @ignore */
var Data = require('../data.js').Data; /** @ignore */
var Link = require('../link.js').Link; /** @ignore */
var NetworkNack = require('../network-nack.js').NetworkNack; /** @ignore */
var Exclude = require('../exclude.js').Exclude; /** @ignore */
var Encryptor = require('./algo/encryptor.js').Encryptor; /** @ignore */
var EncryptParams = require('./algo/encrypt-params.js').EncryptParams; /** @ignore */
var EncryptAlgorithmType = require('./algo/encrypt-params.js').EncryptAlgorithmType; /** @ignore */
var AesKeyParams = require('../security/key-params.js').AesKeyParams; /** @ignore */
var AesAlgorithm = require('./algo/aes-algorithm.js').AesAlgorithm; /** @ignore */
var Schedule = require('./schedule.js').Schedule; /** @ignore */
var EncryptError = require('./encrypt-error.js').EncryptError; /** @ignore */
var NdnCommon = require('../util/ndn-common.js').NdnCommon; /** @ignore */
var SyncPromise = require('../util/sync-promise.js').SyncPromise;

/**
 * A Producer manages content keys used to encrypt a data packet in the
 * group-based encryption protocol.
 * Create a Producer to use the given ProducerDb, Face and other values.
 *
 * A producer can produce data with a naming convention:
 *   /<prefix>/SAMPLE/<dataType>/[timestamp]
 *
 * The produced data packet is encrypted with a content key,
 * which is stored in the ProducerDb database.
 *
 * A producer also needs to produce data containing a content key
 * encrypted with E-KEYs. A producer can retrieve E-KEYs through the face,
 * and will re-try for at most repeatAttemps times when E-KEY retrieval fails.
 *
 * @param {Name} prefix The producer name prefix. This makes a copy of the Name.
 * @param {Name} dataType The dataType portion of the producer name. This makes
 * a copy of the Name.
 * @param {Face} face The face used to retrieve keys.
 * @param {KeyChain} keyChain The keyChain used to sign data packets.
 * @param {ProducerDb} database The ProducerDb database for storing keys.
 * @param {number} repeatAttempts (optional) The maximum retry for retrieving
 * keys. If omitted, use a default value of 3.
 * @param {Link} keyRetrievalLink (optional) The Link object to use in Interests
 * for key retrieval. This makes a copy of the Link object. If the Link object's
 * getDelegations().size() is zero, don't use it. If omitted, don't use a Link
 * object.
 * @note This class is an experimental feature. The API may change.
 * @constructor
 */
var Producer = function Producer
  (prefix, dataType, face, keyChain, database, repeatAttempts, keyRetrievalLink)
{
  this.face_ = face;
  this.keyChain_ = keyChain;
  this.database_ = database;
  this.maxRepeatAttempts_ = (repeatAttempts == undefined ? 3 : repeatAttempts);
  this.keyRetrievalLink_ =
    (keyRetrievalLink == undefined ? Producer.NO_LINK : new Link(keyRetrievalLink));

  // The map key is the key name URI string. The value is an object with fields
  // "keyName" and "keyInfo" where "keyName" is the same Name used for the key
  // name URI string, and "keyInfo" is the Producer.KeyInfo_.
  // (Use a string because we can't use the Name object as the key in JavaScript.)
  // (Also put the original Name in the value because we need to iterate over
  // eKeyInfo_ and we don't want to rebuild the Name from the name URI string.)
  this.eKeyInfo_ = {};
  // The map key is the time stamp. The value is a Producer.KeyRequest_.
  this.keyRequests_ = {};

  var fixedPrefix = new Name(prefix);
  var fixedDataType = new Name(dataType);

  // Fill ekeyInfo_ with all permutations of dataType, including the 'E-KEY'
  // component of the name. This will be used in createContentKey to send
  // interests without reconstructing names every time.
  fixedPrefix.append(Encryptor.NAME_COMPONENT_READ);
  while (fixedDataType.size() > 0) {
    var nodeName = new Name(fixedPrefix);
    nodeName.append(fixedDataType);
    nodeName.append(Encryptor.NAME_COMPONENT_E_KEY);

    this.eKeyInfo_[nodeName.toUri()] =
      { keyName: nodeName, keyInfo: new Producer.KeyInfo_() };
    fixedDataType = fixedDataType.getPrefix(-1);
  }
  fixedPrefix.append(dataType);
  this.namespace_ = new Name(prefix);
  this.namespace_.append(Encryptor.NAME_COMPONENT_SAMPLE);
  this.namespace_.append(dataType);
};

exports.Producer = Producer;

/**
 * Create the content key corresponding to the timeSlot. This first checks if
 * the content key exists. For an existing content key, this returns the
 * content key name directly. If the key does not exist, this creates one and
 * encrypts it using the corresponding E-KEYs. The encrypted content keys are
 * passed to the onEncryptedKeys callback.
 * @param {number} timeSlot The time slot as milliseconds since Jan 1, 1970 UTC.
 * @param {function} onEncryptedKeys If this creates a content key, then this
 * calls onEncryptedKeys(keys) where keys is a list of encrypted content key
 * Data packets. If onEncryptedKeys is null, this does not use it.
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onContentKeyName This calls onContentKeyName(contentKeyName)
 * with the content key name for the time slot. If onContentKeyName is null,
 * this does not use it. (A callback is needed because of async database
 * operations.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onError (optional) This calls onError(errorCode, message)
 * for an error, where errorCode is from EncryptError.ErrorCode and message is a
 * string. If omitted, use a default callback which does nothing.
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 */
Producer.prototype.createContentKey = function
  (timeSlot, onEncryptedKeys, onContentKeyName, onError)
{
  if (!onError)
    onError = Producer.defaultOnError;

  var hourSlot = Producer.getRoundedTimeSlot_(timeSlot);

  // Create the content key name.
  var contentKeyName = new Name(this.namespace_);
  contentKeyName.append(Encryptor.NAME_COMPONENT_C_KEY);
  contentKeyName.append(Schedule.toIsoString(hourSlot));

  var contentKeyBits;
  var thisProducer = this;

  // Check if we have created the content key before.
  this.database_.hasContentKeyPromise(timeSlot)
  .then(function(exists) {
    if (exists) {
      if (onContentKeyName != null)
        onContentKeyName(contentKeyName);
      return;
    }

    // We haven't created the content key. Create one and add it into the database.
    var aesParams = new AesKeyParams(128);
    contentKeyBits = AesAlgorithm.generateKey(aesParams).getKeyBits();
    thisProducer.database_.addContentKeyPromise(timeSlot, contentKeyBits)
    .then(function() {
      // Now we need to retrieve the E-KEYs for content key encryption.
      var timeCount = Math.round(timeSlot);
      thisProducer.keyRequests_[timeCount] =
        new Producer.KeyRequest_(thisProducer.getEKeyInfoSize_());
      var keyRequest = thisProducer.keyRequests_[timeCount];

      // Check if the current E-KEYs can cover the content key.
      var timeRange = new Exclude();
      Producer.excludeAfter
        (timeRange, new Name.Component(Schedule.toIsoString(timeSlot)));
      for (var keyNameUri in thisProducer.eKeyInfo_) {
         // For each current E-KEY.
        var entry = thisProducer.eKeyInfo_[keyNameUri];
        var keyInfo = entry.keyInfo;
        if (timeSlot < keyInfo.beginTimeSlot || timeSlot >= keyInfo.endTimeSlot) {
          // The current E-KEY cannot cover the content key, so retrieve one.
          keyRequest.repeatAttempts[keyNameUri] = 0;
          thisProducer.sendKeyInterest_
            (new Interest(entry.keyName).setExclude(timeRange).setChildSelector(1),
             timeSlot, onEncryptedKeys, onError);
        }
        else {
          // The current E-KEY can cover the content key.
          // Encrypt the content key directly.
          var eKeyName = new Name(entry.keyName);
          eKeyName.append(Schedule.toIsoString(keyInfo.beginTimeSlot));
          eKeyName.append(Schedule.toIsoString(keyInfo.endTimeSlot));
          thisProducer.encryptContentKeyPromise_
            (keyInfo.keyBits, eKeyName, timeSlot, onEncryptedKeys, onError);
        }
      }

      if (onContentKeyName != null)
        onContentKeyName(contentKeyName);
    });
  });
};

/**
 * Encrypt the given content with the content key that covers timeSlot, and
 * update the data packet with the encrypted content and an appropriate data
 * name.
 * @param {Data} data An empty Data object which is updated.
 * @param {number} timeSlot The time slot as milliseconds since Jan 1, 1970 UTC.
 * @param {Blob} content The content to encrypt.
 * @param {function} onComplete This calls onComplete() when the data packet has
 * been updated.
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onError (optional) This calls onError(errorCode, message)
 * for an error, where errorCode is from EncryptError.ErrorCode and message is a
 * string. If omitted, use a default callback which does nothing.
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 */
Producer.prototype.produce = function
  (data, timeSlot, content, onComplete, onError)
{
  if (!onError)
    onError = Producer.defaultOnError;

  var thisProducer = this;

  // Get a content key.
  this.createContentKey(timeSlot, null, function(contentKeyName) {
    thisProducer.database_.getContentKeyPromise(timeSlot)
    .then(function(contentKey) {
      // Produce data.
      var dataName = new Name(thisProducer.namespace_);
      dataName.append(Schedule.toIsoString(timeSlot));

      data.setName(dataName);
      var params = new EncryptParams(EncryptAlgorithmType.AesCbc, 16);
      return Encryptor.encryptData
        (data, content, contentKeyName, contentKey, params);
    })
    .then(function() {
      return thisProducer.keyChain_.signPromise(data);
    })
    .then(function() {
      try {
        onComplete();
      } catch (ex) {
        console.log("Error in onComplete: " + NdnCommon.getErrorWithStackTrace(ex));
      }
    }, function(error) {
      try {
        onError(EncryptError.ErrorCode.General, "" + error);
      } catch (ex) {
        console.log("Error in onError: " + NdnCommon.getErrorWithStackTrace(ex));
      }
    });
  }, onError);
};

/**
 * The default onError callback which does nothing.
 */
Producer.defaultOnError = function(errorCode, message)
{
  // Do nothing.
};

Producer.KeyInfo_ = function ProducerKeyInfo()
{
  this.beginTimeSlot = 0.0;
  this.endTimeSlot = 0.0;
  this.keyBits = null; // Blob
};

Producer.KeyRequest_ = function ProducerKeyRequest(interests)
{
  this.interestCount = interests; // number
  // The map key is the name URI string. The value is an int count.
  // (Use a string because we can't use the Name object as the key in JavaScript.)
  this.repeatAttempts = {};
  this.encryptedKeys = []; // of Data
};

/**
 * Round timeSlot to the nearest whole hour, so that we can store content keys
 * uniformly (by start of the hour).
 * @param {number} timeSlot The time slot as milliseconds since Jan 1, 1970 UTC.
 * @return {number} The start of the hour as milliseconds since Jan 1, 1970 UTC.
 */
Producer.getRoundedTimeSlot_ = function(timeSlot)
{
  return Math.round(Math.floor(Math.round(timeSlot) / 3600000.0) * 3600000.0);
}

/**
 * Send an interest with the given name through the face with callbacks to
 * handleCoveringKey_, handleTimeout_ and handleNetworkNack_.
 * @param {Interest} interest The interest to send.
 * @param {number} timeSlot The time slot, passed to handleCoveringKey_,
 * handleTimeout_ and handleNetworkNack_.
 * @param {function} onEncryptedKeys The OnEncryptedKeys callback, passed to
 * handleCoveringKey_, handleTimeout_ and handleNetworkNack_.
 * @param {function} onError This calls onError(errorCode, message) for an error.
 */
Producer.prototype.sendKeyInterest_ = function
  (interest, timeSlot, onEncryptedKeys, onError)
{
  var thisProducer = this;

  function onKey(interest, data) {
    thisProducer.handleCoveringKey_
      (interest, data, timeSlot, onEncryptedKeys, onError);
  }

  function onTimeout(interest) {
    thisProducer.handleTimeout_(interest, timeSlot, onEncryptedKeys, onError);
  }

  function onNetworkNack(interest, networkNack) {
    thisProducer.handleNetworkNack_
      (interest, networkNack, timeSlot, onEncryptedKeys, onError);
  }

  var request;
  if (this.keyRetrievalLink_.getDelegations().size() === 0)
    // We can use the supplied interest without copying.
    request = interest;
  else {
    // Copy the supplied interest and add the Link.
    request = new Interest(interest);
    // This will use a cached encoding if available.
    request.setLinkWireEncoding(this.keyRetrievalLink_.wireEncode());
  }

  this.face_.expressInterest(request, onKey, onTimeout, onNetworkNack);
};

/**
 * This is called from an expressInterest timeout to update the state of
 * keyRequest. Re-express the interest if the number of retrials is less than
 * the max limit.
 * @param {Interest} interest The timed-out interest.
 * @param {number} timeSlot The time slot as milliseconds since Jan 1, 1970 UTC.
 * @param {function} onEncryptedKeys When there are no more interests to process,
 * this calls onEncryptedKeys(keys) where keys is a list of encrypted content
 * key Data packets. If onEncryptedKeys is null, this does not use it.
 * @param {function} onError This calls onError(errorCode, message) for an error.
 */
Producer.prototype.handleTimeout_ = function
  (interest, timeSlot, onEncryptedKeys, onError)
{
  var timeCount = Math.round(timeSlot);
  var keyRequest = this.keyRequests_[timeCount];

  var interestName = interest.getName();
  var interestNameUri = interestName.toUri();

  if (keyRequest.repeatAttempts[interestNameUri] < this.maxRepeatAttempts_) {
    // Increase the retrial count.
    ++keyRequest.repeatAttempts[interestNameUri];
    this.sendKeyInterest_(interest, timeSlot, onEncryptedKeys, onError);
  }
  else
    // Treat an eventual timeout as a network Nack.
    this.handleNetworkNack_
      (interest, new NetworkNack(), timeSlot, onEncryptedKeys, onError);
};

/**
 * This is called from an expressInterest OnNetworkNack to handle a network
 * Nack for the E-KEY requested through the Interest. Decrease the outstanding
 * E-KEY interest count for the C-KEY corresponding to the timeSlot.
 * @param {Interest} interest The interest given to expressInterest.
 * @param {NetworkNack} networkNack The returned NetworkNack (unused).
 * @param {number} timeSlot The time slot as milliseconds since Jan 1, 1970 UTC.
 * @param {function} onEncryptedKeys When there are no more interests to process,
 * this calls onEncryptedKeys(keys) where keys is a list of encrypted content
 * key Data packets. If onEncryptedKeys is null, this does not use it.
 */
Producer.prototype.handleNetworkNack_ = function
  (interest, networkNack, timeSlot, onEncryptedKeys, onError)
{
  // We have run out of options....
  var timeCount = Math.round(timeSlot);
  this.updateKeyRequest_
    (this.keyRequests_[timeCount], timeCount, onEncryptedKeys);
};

/**
 * Decrease the count of outstanding E-KEY interests for the C-KEY for
 * timeCount. If the count decreases to 0, invoke onEncryptedKeys.
 * @param {Producer.KeyRequest_} keyRequest The KeyRequest with the
 * interestCount to update.
 * @param {number} timeCount The time count for indexing keyRequests_.
 * @param {function} onEncryptedKeys When there are no more interests to
 * process, this calls onEncryptedKeys(keys) where keys is a list of encrypted
 * content key Data packets. If onEncryptedKeys is null, this does not use it.
 */
Producer.prototype.updateKeyRequest_ = function
  (keyRequest, timeCount, onEncryptedKeys)
{
  --keyRequest.interestCount;
  if (keyRequest.interestCount == 0 && onEncryptedKeys != null) {
    try {
      onEncryptedKeys(keyRequest.encryptedKeys);
    } catch (ex) {
      console.log("Error in onEncryptedKeys: " + NdnCommon.getErrorWithStackTrace(ex));
    }
    delete this.keyRequests_[timeCount];
  }
};

/**
 * This is called from an expressInterest OnData to check that the encryption
 * key contained in data fits the timeSlot. This sends a refined interest if
 * required.
 * @param {Interest} interest The interest given to expressInterest.
 * @param {Data} data The fetched Data packet.
 * @param {number} timeSlot The time slot as milliseconds since Jan 1, 1970 UTC.
 * @param {function} onEncryptedKeys When there are no more interests to process,
 * this calls onEncryptedKeys(keys) where keys is a list of encrypted content
 * key Data packets. If onEncryptedKeys is null, this does not use it.
 * @param {function} onError This calls onError(errorCode, message) for an error.
 */
Producer.prototype.handleCoveringKey_ = function
  (interest, data, timeSlot, onEncryptedKeys, onError)
{
  var timeCount = Math.round(timeSlot);
  var keyRequest = this.keyRequests_[timeCount];

  var interestName = interest.getName();
  var interestNameUrl = interestName.toUri();
  var keyName = data.getName();

  var begin = Schedule.fromIsoString
    (keyName.get(Producer.START_TIME_STAMP_INDEX).getValue().toString());
  var end = Schedule.fromIsoString
    (keyName.get(Producer.END_TIME_STAMP_INDEX).getValue().toString());

  if (timeSlot >= end) {
    // If the received E-KEY covers some earlier period, try to retrieve an
    // E-KEY covering a later one.
    var timeRange = new Exclude(interest.getExclude());
    Producer.excludeBefore(timeRange, keyName.get(Producer.START_TIME_STAMP_INDEX));
    keyRequest.repeatAttempts[interestNameUrl] = 0;
    this.sendKeyInterest_
      (new Interest(interestName).setExclude(timeRange).setChildSelector(1),
       timeSlot, onEncryptedKeys, onError);
  }
  else {
    // If the received E-KEY covers the content key, encrypt the content.
    var encryptionKey = data.getContent();
    var thisProducer = this;
    this.encryptContentKeyPromise_
      (encryptionKey, keyName, timeSlot, onEncryptedKeys, onError)
    .then(function(success) {
      if (success) {
        var keyInfo = thisProducer.eKeyInfo_[interestNameUrl].keyInfo;
        keyInfo.beginTimeSlot = begin;
        keyInfo.endTimeSlot = end;
        keyInfo.keyBits = encryptionKey;
      }
    });
  }
};

/**
 * Get the content key from the database_ and encrypt it for the timeSlot
 * using encryptionKey.
 * @param {Blob} encryptionKey The encryption key value.
 * @param {Name} eKeyName The key name for the EncryptedContent.
 * @param {number} timeSlot The time slot as milliseconds since Jan 1, 1970 UTC.
 * @param {function} onEncryptedKeys When there are no more interests to process,
 * this calls onEncryptedKeys(keys) where keys is a list of encrypted content
 * key Data packets. If onEncryptedKeys is null, this does not use it.
 * @param {function} onError This calls onError(errorCode, message) for an error.
 * @return {Promise} A promise that returns true if encryption succeeds,
 * otherwise false.
 */
Producer.prototype.encryptContentKeyPromise_ = function
  (encryptionKey, eKeyName, timeSlot, onEncryptedKeys, onError)
{
  var timeCount = Math.round(timeSlot);
  var keyRequest = this.keyRequests_[timeCount];

  var keyName = new Name(this.namespace_);
  keyName.append(Encryptor.NAME_COMPONENT_C_KEY);
  keyName.append(Schedule.toIsoString(Producer.getRoundedTimeSlot_(timeSlot)));

  var cKeyData;
  var thisProducer = this;

  return this.database_.getContentKeyPromise(timeSlot)
  .then(function(contentKey) {
    cKeyData = new Data();
    cKeyData.setName(keyName);
    var params = new EncryptParams(EncryptAlgorithmType.RsaOaep);
    return Encryptor.encryptDataPromise
      (cKeyData, contentKey, eKeyName, encryptionKey, params);
  })
  .then(function() {
    return SyncPromise.resolve(true);
  }, function(error) {
    try {
      onError(EncryptError.ErrorCode.EncryptionFailure,
              "encryptData failed: " + error);
    } catch (ex) {
      console.log("Error in onError: " + NdnCommon.getErrorWithStackTrace(ex));
    }
    return SyncPromise.resolve(false);
  })
  .then(function(success) {
    if (success) {
      return thisProducer.keyChain_.signPromise(cKeyData)
      .then(function() {
        keyRequest.encryptedKeys.push(cKeyData);
        thisProducer.updateKeyRequest_(keyRequest, timeCount, onEncryptedKeys);
        return SyncPromise.resolve(true);
      });
    }
    else
      return SyncPromise.resolve(false);
  });
};

Producer.prototype.getEKeyInfoSize_ = function()
{
  // Note: This is really a method to find the key count in any object, but we
  // don't want to claim that it is a tested and general utility method.
  var size = 0;
  for (key in this.eKeyInfo_) {
    if (this.eKeyInfo_.hasOwnProperty(key))
      ++size;
  }

  return size;
};

// TODO: Move this to be the main representation inside the Exclude object.
/**
 * Create a new ExcludeEntry.
 * @param {Name.Component} component
 * @param {boolean} anyFollowsComponent
 */
Producer.ExcludeEntry = function ExcludeEntry(component, anyFollowsComponent)
{
  this.component_ = component;
  this.anyFollowsComponent_ = anyFollowsComponent;
};

/**
 * Create a list of ExcludeEntry from the Exclude object.
 * @param {Exclude} exclude The Exclude object to read.
 * @return {Array<ExcludeEntry>} A new array of ExcludeEntry.
 */
Producer.getExcludeEntries = function(exclude)
{
  var entries = [];

  for (var i = 0; i < exclude.size(); ++i) {
    if (exclude.get(i) == Exclude.ANY) {
      if (entries.length == 0)
        // Add a "beginning ANY".
        entries.push(new Producer.ExcludeEntry(new Name.Component(), true));
      else
        // Set anyFollowsComponent of the final component.
        entries[entries.length - 1].anyFollowsComponent_ = true;
    }
    else
      entries.push(new Producer.ExcludeEntry(exclude.get(i), false));
  }

  return entries;
};

/**
 * Set the Exclude object from the array of ExcludeEntry.
 * @param {Exclude} exclude The Exclude object to update.
 * @param {Array<ExcludeEntry>} entries The array of ExcludeEntry.
 */
Producer.setExcludeEntries = function(exclude, entries)
{
  exclude.clear();

  for (var i = 0; i < entries.length; ++i) {
    var entry = entries[i];

    if (i == 0 && entry.component_.getValue().size() == 0 &&
        entry.anyFollowsComponent_)
      // This is a "beginning ANY".
      exclude.appendAny();
    else {
      exclude.appendComponent(entry.component_);
      if (entry.anyFollowsComponent_)
        exclude.appendAny();
    }
  }
};

/**
 * Get the latest entry in the array whose component_ is less than or equal to
 * component.
 * @param {Array<ExcludeEntry>} entries The array of ExcludeEntry.
 * @param {Name.Component} component The component to compare.
 * @return {number} The index of the found entry, or -1 if not found.
 */
Producer.findEntryBeforeOrAt = function(entries, component)
{
  var i = entries.length - 1;
  while (i >= 0) {
    if (entries[i].component_.compare(component) <= 0)
      break;
    --i;
  }

  return i;
};

/**
 * Exclude all components in the range beginning at "from".
 * @param {Exclude} exclude The Exclude object to update.
 * @param {Name.Component} from The first component in the exclude range.
 */
Producer.excludeAfter = function(exclude, from)
{
  var entries = Producer.getExcludeEntries(exclude);

  var iNewFrom;
  var iFoundFrom = Producer.findEntryBeforeOrAt(entries, from);
  if (iFoundFrom < 0) {
    // There is no entry before "from" so insert at the beginning.
    entries.splice(0, 0, new Producer.ExcludeEntry(from, true));
    iNewFrom = 0;
  }
  else {
    var foundFrom = entries[iFoundFrom];

    if (!foundFrom.anyFollowsComponent_) {
      if (foundFrom.component_.equals(from)) {
        // There is already an entry with "from", so just set the "ANY" flag.
        foundFrom.anyFollowsComponent_ = true;
        iNewFrom = iFoundFrom;
      }
      else {
        // Insert following the entry before "from".
        entries.splice(iFoundFrom + 1, 0, new Producer.ExcludeEntry(from, true));
        iNewFrom = iFoundFrom + 1;
      }
    }
    else
      // The entry before "from" already has an "ANY" flag, so do nothing.
      iNewFrom = iFoundFrom;
  }

  // Remove intermediate entries since they are inside the range.
  var iRemoveBegin = iNewFrom + 1;
  var nRemoveNeeded = entries.length - iRemoveBegin;
  entries.splice(iRemoveBegin, nRemoveNeeded);

  Producer.setExcludeEntries(exclude, entries);
};

/**
 * Exclude all components in the range ending at "to".
 * @param {Exclude} exclude The Exclude object to update.
 * @param {Name.Component} to The last component in the exclude range.
 */
Producer.excludeBefore = function(exclude, to)
{
  Producer.excludeRange(exclude, new Name.Component(), to);
};

/**
 * Exclude all components in the range beginning at "from" and ending at "to".
 * @param {Exclude} exclude The Exclude object to update.
 * @param {Name.Component} from The first component in the exclude range.
 * @param {Name.Component} to The last component in the exclude range.
 */
Producer.excludeRange = function(exclude, from, to)
{
  if (from.compare(to) >= 0) {
    if (from.compare(to) == 0)
      throw new Error
        ("excludeRange: from == to. To exclude a single component, sue excludeOne.");
    else
      throw new Error
        ("excludeRange: from must be less than to. Invalid range: [" +
         from.toEscapedString() + ", " + to.toEscapedString() + "]");
  }

  var entries = Producer.getExcludeEntries(exclude);

  var iNewFrom;
  var iFoundFrom = Producer.findEntryBeforeOrAt(entries, from);
  if (iFoundFrom < 0) {
    // There is no entry before "from" so insert at the beginning.
    entries.splice(0, 0, new Producer.ExcludeEntry(from, true));
    iNewFrom = 0;
  }
  else {
    var foundFrom = entries[iFoundFrom];

    if (!foundFrom.anyFollowsComponent_) {
      if (foundFrom.component_.equals(from)) {
        // There is already an entry with "from", so just set the "ANY" flag.
        foundFrom.anyFollowsComponent_ = true;
        iNewFrom = iFoundFrom;
      }
      else {
        // Insert following the entry before "from".
        entries.splice(iFoundFrom + 1, 0, new Producer.ExcludeEntry(from, true));
        iNewFrom = iFoundFrom + 1;
      }
    }
    else
      // The entry before "from" already has an "ANY" flag, so do nothing.
      iNewFrom = iFoundFrom;
  }

  // We have at least one "from" before "to", so we know this will find an entry.
  var iFoundTo = Producer.findEntryBeforeOrAt(entries, to);
  var foundTo = entries[iFoundTo];
  if (iFoundTo == iNewFrom)
    // Insert the "to" immediately after the "from".
    entries.splice(iNewFrom + 1, 0, new Producer.ExcludeEntry(to, false));
  else {
    var iRemoveEnd;
    if (!foundTo.anyFollowsComponent_) {
      if (foundTo.component_.equals(to))
        // The "to" entry already exists. Remove up to it.
        iRemoveEnd = iFoundTo;
      else {
        // Insert following the previous entry, which will be removed.
        entries.splice(iFoundTo + 1, 0, new Producer.ExcludeEntry(to, false));
        iRemoveEnd = iFoundTo + 1;
      }
    }
    else
      // "to" follows a component which is already followed by "ANY", meaning
      // the new range now encompasses it, so remove the component.
      iRemoveEnd = iFoundTo + 1;

    // Remove intermediate entries since they are inside the range.
    var iRemoveBegin = iNewFrom + 1;
    var nRemoveNeeded = iRemoveEnd - iRemoveBegin;
    entries.splice(iRemoveBegin, nRemoveNeeded);
  }

  Producer.setExcludeEntries(exclude, entries);
};

Producer.START_TIME_STAMP_INDEX = -2;
Producer.END_TIME_STAMP_INDEX = -1;
Producer.NO_LINK = new Link();
