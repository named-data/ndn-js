/**
 * This class represents the digest tree for chrono-sync2013.
 * Copyright (C) 2014-2018 Regents of the University of California.
 * @author: Zhehao Wang, based on Jeff T.'s implementation in ndn-cpp
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
var DigestTree = require('./digest-tree.js').DigestTree; /** @ignore */
var Interest = require('../interest.js').Interest; /** @ignore */
var Data = require('../data.js').Data; /** @ignore */
var Name = require('../name.js').Name; /** @ignore */
var Blob = require('../util/blob.js').Blob; /** @ignore */
var MemoryContentCache = require('../util/memory-content-cache.js').MemoryContentCache; /** @ignore */
var SyncStateProto = require('./sync-state.js').SyncStateProto; /** @ignore */
var NdnCommon = require('../util/ndn-common.js').NdnCommon;

/**
 * ChronoSync2013 implements the NDN ChronoSync protocol as described in the
 * 2013 paper "Let's ChronoSync: Decentralized Dataset State Synchronization in
 * Named Data Networking". http://named-data.net/publications/chronosync .
 * @note The support for ChronoSync is experimental and the API is not finalized.
 * See the API docs for more detail at
 * http://named-data.net/doc/ndn-ccl-api/chrono-sync2013.html .
 *
 * Create a new ChronoSync2013 to communicate using the given face. Initialize
 * the digest log with a digest of "00" and and empty content. Register the
 * applicationBroadcastPrefix to receive interests for sync state messages and
 * express an interest for the initial root digest "00".
 * @param {function} onReceivedSyncState When ChronoSync receives a sync state message,
 * this calls onReceivedSyncState(syncStates, isRecovery) where syncStates is the
 * list of SyncState messages and isRecovery is true if this is the initial
 * list of SyncState messages or from a recovery interest. (For example, if
 * isRecovery is true, a chat application would not want to re-display all
 * the associated chat messages.) The callback should send interests to fetch
 * the application data for the sequence numbers in the sync state.
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onInitialized This calls onInitialized() when the first sync data
 * is received (or the interest times out because there are no other
 * publishers yet).
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {Name} applicationDataPrefix The prefix used by this application instance
 * for application data. For example, "/my/local/prefix/ndnchat4/0K4wChff2v".
 * This is used when sending a sync message for a new sequence number.
 * In the sync message, this uses applicationDataPrefix.toUri().
 * @param {Name} applicationBroadcastPrefix The broadcast name prefix including the
 * application name. For example, "/ndn/broadcast/ChronoChat-0.3/ndnchat1".
 * This makes a copy of the name.
 * @param {int} sessionNo The session number used with the applicationDataPrefix in
 * sync state messages.
 * @param {Face} face The Face for calling registerPrefix and expressInterest. The
 * Face object must remain valid for the life of this ChronoSync2013 object.
 * @param {KeyChain} keyChain To sign a data packet containing a sync state message, this
 * calls keyChain.sign(data, certificateName).
 * @param {Name} certificateName The certificate name of the key to use for signing a
 * data packet containing a sync state message.
 * @param {Milliseconds} syncLifetime The interest lifetime in milliseconds for sending
 * sync interests.
 * @param {function} onRegisterFailed If failed to register the prefix to receive
 * interests for the applicationBroadcastPrefix, this calls
 * onRegisterFailed(applicationBroadcastPrefix).
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @constructor
 */
var ChronoSync2013 = function ChronoSync2013
  (onReceivedSyncState, onInitialized, applicationDataPrefix,
   applicationBroadcastPrefix, sessionNo, face, keyChain, certificateName,
   syncLifetime, onRegisterFailed)
{
  // assigning function pointers
  this.onReceivedSyncState = onReceivedSyncState;
  this.onInitialized = onInitialized;
  this.applicationDataPrefixUri = applicationDataPrefix.toUri();
  this.applicationBroadcastPrefix = applicationBroadcastPrefix;
  this.session = sessionNo;
  this.face = face;
  this.keyChain = keyChain;
  this.certificateName = certificateName;
  this.sync_lifetime = syncLifetime;
  this.usrseq = -1;

  this.digest_tree = new DigestTree();
  this.contentCache = new MemoryContentCache(face);

  this.digest_log = new Array();
  this.digest_log.push(new ChronoSync2013.DigestLogEntry("00",[]));

  this.contentCache.registerPrefix
    (this.applicationBroadcastPrefix, onRegisterFailed,
     this.onInterest.bind(this));
  this.enabled = true;

  var interest = new Interest(this.applicationBroadcastPrefix);
  interest.getName().append("00");

  interest.setInterestLifetimeMilliseconds(1000);

  var Sync;
  try {
    // Using protobuf.min.js in the browser.
    Sync = dcodeIO.ProtoBuf.newBuilder().import(SyncStateProto).build("Sync");
  }
  catch (ex) {
    // Using protobufjs in node.
    Sync = require("protobufjs").newBuilder().import(SyncStateProto).build("Sync");
  }
  this.SyncStateMsg = Sync.SyncStateMsg;
  this.SyncState = Sync.SyncState;

  this.face.expressInterest(interest, this.onData.bind(this), this.initialTimeOut.bind(this));
};

exports.ChronoSync2013 = ChronoSync2013;

/**
 * Get a copy of the current list of producer data prefixes, and the
 * associated session number. You can use these in getProducerSequenceNo().
 * This includes the prefix for this user.
 * @return Array<ChronoSync2013.PrefixAndSessionNo> A copy of the list of each
 * producer prefix and session number.
 */
ChronoSync2013.prototype.getProducerPrefixes = function()
{
  var prefixes = [];

  for (var i = 0; i < this.digest_tree.digestnode.length; ++i) {
    var node = this.digest_tree.get(i);
    prefixes.push
      (new ChronoSync2013.PrefixAndSessionNo
       (node.getDataPrefix(), node.getSessionNo()));
  }
  return prefixes;
};

/**
 * Get the current sequence number in the digest tree for the given
 * producer dataPrefix and sessionNo.
 * @param {string} dataPrefix The producer data prefix as a Name URI string.
 * @param {number} sessionNo The producer session number.
 * @return {number} The current producer sequence number, or -1 if the producer
 * namePrefix and sessionNo are not in the digest tree.
 */
ChronoSync2013.prototype.getProducerSequenceNo = function(dataPrefix, sessionNo)
{
  var index = this.digest_tree.find(dataPrefix, sessionNo);
  if (index < 0)
    return -1;
  else
    return this.digest_tree.get(index).getSequenceNo();
};

/**
 * Increment the sequence number, create a sync message with the new sequence number,
 * and publish a data packet where the name is applicationBroadcastPrefix + root
 * digest of current digest tree. Then add the sync message to digest tree and digest
 * log which creates a new root digest. Finally, express an interest for the next sync
 * update with the name applicationBroadcastPrefix + the new root digest.
 * After this, application should publish the content for the new sequence number.
 * Get the new sequence number with getSequenceNo().
 * @param {Blob} applicationInfo (optional) This appends applicationInfo to the
 * content of the sync messages. This same info is provided to the receiving
 * application in the SyncState state object provided to the
 * onReceivedSyncState callback.
 */
ChronoSync2013.prototype.publishNextSequenceNo = function(applicationInfo)
{
  applicationInfo = applicationInfo instanceof Blob ?
    applicationInfo : new Blob(applicationInfo, true);

  this.usrseq ++;
  var fields = { name: this.applicationDataPrefixUri,
                 type: 'UPDATE',
                 seqno:{
                   seq: this.usrseq,
                   session: this.session
                 }
               };
  if (!applicationInfo.isNull() && applicationInfo.size() > 0)
    fields.application_info = applicationInfo.buf();
  var content = [new this.SyncState(fields)];
  var content_t = new this.SyncStateMsg({ss:content});
  this.broadcastSyncState(this.digest_tree.getRoot(), content_t);

  if (!this.update(content))
    console.log("Warning: ChronoSync: update did not create a new digest log entry");

  var interest = new Interest(this.applicationBroadcastPrefix);
  interest.getName().append(this.digest_tree.getRoot());
  interest.setInterestLifetimeMilliseconds(this.sync_lifetime);

  this.face.expressInterest(interest, this.onData.bind(this), this.syncTimeout.bind(this));
};

/**
 * Get the sequence number of the latest data published by this application instance.
 * @return {int} the sequence number
 */
ChronoSync2013.prototype.getSequenceNo = function()
{
  return this.usrseq;
};

// DigestLogEntry class

ChronoSync2013.DigestLogEntry = function ChronoSync2013DisgestLogEntry(digest, data)
{
  this.digest = digest;
  this.data = data;
};

ChronoSync2013.DigestLogEntry.prototype.getDigest = function()
{
  return this.digest;
};

ChronoSync2013.DigestLogEntry.prototype.getData = function()
{
  return this.data;
};

/**
 * Unregister callbacks so that this does not respond to interests anymore.
 * If you will dispose this ChronoSync2013 object while your application is
 * still running, you should call shutdown() first.  After calling this, you
 * should not call publishNextSequenceNo() again since the behavior will be
 * undefined.
 */
ChronoSync2013.prototype.shutdown = function()
{
  this.enabled = false;
  this.contentCache.unregisterAll();
};

// SyncState class
/**
 * A SyncState holds the values of a sync state message which is passed to the
 * onReceivedSyncState callback which was given to the ChronoSyn2013
 * constructor. Note: this has the same info as the Protobuf class
 * Sync.SyncState, but we make a separate class so that we don't need the
 * Protobuf definition in the ChronoSync API.
 */
ChronoSync2013.SyncState = function ChronoSync2013SyncState
  (dataPrefixUri, sessionNo, sequenceNo, applicationInfo)
{
  this.dataPrefixUri_ = dataPrefixUri;
  this.sessionNo_ = sessionNo;
  this.sequenceNo_ = sequenceNo;
  this.applicationInfo_ = applicationInfo;
};

/**
 * Get the application data prefix for this sync state message.
 * @return The application data prefix as a Name URI string.
 */
ChronoSync2013.SyncState.prototype.getDataPrefix = function()
{
  return this.dataPrefixUri_;
}

/**
 * Get the session number associated with the application data prefix for
 * this sync state message.
 * @return The session number.
 */
ChronoSync2013.SyncState.prototype.getSessionNo = function()
{
  return this.sessionNo_;
}

/**
 * Get the sequence number for this sync state message.
 * @return The sequence number.
 */
ChronoSync2013.SyncState.prototype.getSequenceNo = function()
{
  return this.sequenceNo_;
}

/**
 * Get the application info which was included when the sender published the
 * next sequence number.
 * @return {Blob} The applicationInfo Blob. If the sender did not provide any,
 * return an isNull Blob.
 */
ChronoSync2013.SyncState.prototype.getApplicationInfo = function()
{
  return this.applicationInfo_;
}

/**
 * A PrefixAndSessionNo holds a user's data prefix and session number (used to
 * return a list from getProducerPrefixes).
 */
ChronoSync2013.PrefixAndSessionNo = function ChronoSync2013PrefixAndSessionNo
  (dataPrefixUri, sessionNo)
{
  this.dataPrefixUri_ = dataPrefixUri;
  this.sessionNo_ = sessionNo;
};

/**
 * Get the application data prefix.
 * @return {string} The application data prefix as a Name URI string.
 */
ChronoSync2013.PrefixAndSessionNo.prototype.getDataPrefix = function()
{
  return this.dataPrefixUri_;
};

/**
 * Get the session number associated with the application data prefix.
 * @return {number] The session number.
 */
ChronoSync2013.PrefixAndSessionNo.prototype.getSessionNo = function()
{
  return this.sessionNo_;
};

// Private methods for ChronoSync2013 class,
/**
 * Make a data packet with the syncMessage and with name applicationBroadcastPrefix + digest.
 * Sign and send.
 * @param {string} The root digest as a hex string for the data packet name.
 * @param {SyncStateMsg} The syncMessage updates the digest tree state with the given digest.
 */
ChronoSync2013.prototype.broadcastSyncState = function(digest, syncMessage)
{
  var array = new Uint8Array(syncMessage.toArrayBuffer());
  var data = new Data(this.applicationBroadcastPrefix);
  data.getName().append(digest);
  data.setContent(new Blob(array, false));
  var thisChronoSync = this;
  this.keyChain.sign(data, this.certificateName, function() {
    thisChronoSync.contentCache.add(data);
  });
};

/**
 * Update the digest tree with the messages in content. If the digest tree root is not in
 * the digest log, also add a log entry with the content.
 * @param {SyncStates[]} The sync state messages
 * @return {bool} True if added a digest log entry (because the updated digest tree root
 * was not in the log), false if didn't add a log entry.
 */
 // Whatever's received by ondata, is pushed into digest log as its data directly
ChronoSync2013.prototype.update = function(content)
{
  for (var i = 0; i < content.length; i++) {
    if (content[i].type == 0) {
      if (this.digest_tree.update(content[i].name, content[i].seqno.session, content[i].seqno.seq)) {
        if (this.applicationDataPrefixUri == content[i].name)
          this.usrseq = content[i].seqno.seq;
      }
    }
  }

  if (this.logfind(this.digest_tree.getRoot()) == -1) {
    var newlog = new ChronoSync2013.DigestLogEntry(this.digest_tree.getRoot(), content);
    this.digest_log.push(newlog);
    return true;
  }
  else
    return false;
};

ChronoSync2013.prototype.logfind = function(digest)
{
  for (var i = 0; i < this.digest_log.length; i++) {
    if(digest == this.digest_log[i].digest)
      return i;
  }
  return -1;
};

/**
 * Process the sync interest from the applicationBroadcastPrefix. If we can't
 * satisfy the interest, add it to the pending interest table in
 * this.contentCache so that a future call to contentCacheAdd may satisfy it.
 */
ChronoSync2013.prototype.onInterest = function
  (prefix, interest, face, interestFilterId, filter)
{
  if (!this.enabled)
    // Ignore callbacks after the application calls shutdown().
    return;

  //search if the digest is already exist in the digest log

  var syncdigest = interest.getName().get(this.applicationBroadcastPrefix.size()).toEscapedString();
  if (interest.getName().size() == this.applicationBroadcastPrefix.size() + 2) {
    syncdigest = interest.getName().get(this.applicationBroadcastPrefix.size() + 1).toEscapedString();
  }
  if (interest.getName().size() == this.applicationBroadcastPrefix.size() + 2 || syncdigest == "00") {
    this.processRecoveryInst(interest, syncdigest, face);
  }
  else {
    this.contentCache.storePendingInterest(interest, face);

    if (syncdigest != this.digest_tree.getRoot()) {
      var index = this.logfind(syncdigest);
      var content = [];
      if(index == -1) {
        var self = this;
        // Are we sure that using a "/local/timeout" interest is the best future call approach?
        var timeout = new Interest(new Name("/local/timeout"));
        timeout.setInterestLifetimeMilliseconds(2000);
        this.face.expressInterest
          (timeout, this.dummyOnData,
           this.judgeRecovery.bind(this, timeout, syncdigest, face));
      }
      else {
        //common interest processing
        this.processSyncInst(index, syncdigest, face);
      }
    }
  }
};

/**
 * Process sync/recovery data.
 * @param {Interest}
 * @param {Data}
 */
ChronoSync2013.prototype.onData = function(interest, co)
{
  if (!this.enabled)
    // Ignore callbacks after the application calls shutdown().
    return;

  var arr = new Uint8Array(co.getContent().size());
  arr.set(co.getContent().buf());
  var content_t = this.SyncStateMsg.decode(arr.buffer);
  var content = content_t.ss;

  var isRecovery = false;

  if (this.digest_tree.getRoot() == "00") {
    isRecovery = true;
    this.initialOndata(content);
  }
  else {
    this.update(content);
    if (interest.getName().size() == this.applicationBroadcastPrefix.size() + 2)
      // Assume this is a recovery interest.
      isRecovery = true;
    else
      isRecovery = false;
  }

  // Send the interests to fetch the application data.
  var syncStates = [];

  for (var i = 0; i < content.length; i++) {
    // Only report UPDATE sync states.
    if (content[i].type == 0) {
      var applicationInfo;
      if (content[i].application_info) {
        var binaryInfo = content[i].application_info.toBinary();
        if (binaryInfo.length > 0)
          applicationInfo = new Blob(new Buffer(binaryInfo, "binary"), false);
        else
          applicationInfo = new Blob();
      }
      else
        applicationInfo = new Blob();

      syncStates.push(new ChronoSync2013.SyncState
        (content[i].name, content[i].seqno.session, content[i].seqno.seq,
         applicationInfo));
    }
  }

  // Instead of using Protobuf, use our own definition of SyncStates to pass to onReceivedSyncState.
  try {
    this.onReceivedSyncState(syncStates, isRecovery);
  } catch (ex) {
    console.log("Error in onReceivedSyncState: " + NdnCommon.getErrorWithStackTrace(ex));
  }

  var n = new Name(this.applicationBroadcastPrefix);
  n.append(this.digest_tree.getRoot());

  var interest = new Interest(n);
  interest.setInterestLifetimeMilliseconds(this.sync_lifetime);

  this.face.expressInterest(interest, this.onData.bind(this), this.syncTimeout.bind(this));
};

/**
 * Interest variable not actually in use here
 */
ChronoSync2013.prototype.initialTimeOut = function(interest)
{
  if (!this.enabled)
    // Ignore callbacks after the application calls shutdown().
    return;

  console.log("no other people");

  this.usrseq++;
  try {
    this.onInitialized();
  } catch (ex) {
    console.log("Error in onInitialized: " + NdnCommon.getErrorWithStackTrace(ex));
  }
  var content = [new this.SyncState({ name:this.applicationDataPrefixUri,
                                 type:'UPDATE',
                                 seqno: {
                                   seq:this.usrseq,
                                   session:this.session
                                 }
                               })];
  this.update(content);
  var n = new Name(this.applicationBroadcastPrefix);
  n.append(this.digest_tree.getRoot());
  var retryInterest = new Interest(n);
  retryInterest.setInterestLifetimeMilliseconds(this.sync_lifetime);

  this.face.expressInterest(retryInterest, this.onData.bind(this), this.syncTimeout.bind(this));
};

ChronoSync2013.prototype.processRecoveryInst = function(interest, syncdigest, face)
{
  if (this.logfind(syncdigest) != -1) {
    var content = [];

    for(var i = 0; i < this.digest_tree.digestnode.length; i++) {
      content[i] = new this.SyncState({ name:this.digest_tree.digestnode[i].getDataPrefix(),
                                   type:'UPDATE',
                                   seqno:{
                                     seq:this.digest_tree.digestnode[i].getSequenceNo(),
                                     session:this.digest_tree.digestnode[i].getSessionNo()
                                    }
                                 });
    }

    if (content.length != 0) {
      var content_t = new this.SyncStateMsg({ss:content});
      var str = new Uint8Array(content_t.toArrayBuffer());
      var co = new Data(interest.getName());
      co.setContent(new Blob(str, false));
      if (interest.getName().get(-1).toEscapedString() == "00")
        // Limit the lifetime of replies to interest for "00" since they can be different.
        co.getMetaInfo().setFreshnessPeriod(1000);

      this.keyChain.sign(co, this.certificateName, function() {
        try {
          face.putData(co);
        } catch (e) {
          console.log(e.toString());
        }
      });
    }
  }
};

/**
 * Common interest processing, using digest log to find the difference after syncdigest_t
 * @return True if sent a data packet to satisfy the interest.
 */
ChronoSync2013.prototype.processSyncInst = function(index, syncdigest_t, face)
{
  var content = [];
  var data_name = [];
  var data_seq = [];
  var data_ses = [];

  for (var j = index + 1; j < this.digest_log.length; j++) {
    var temp = this.digest_log[j].getData();
    for (var i = 0 ; i < temp.length ; i++) {
      if (temp[i].type != 0) {
        continue;
      }
      if (this.digest_tree.find(temp[i].name, temp[i].seqno.session) != -1) {
        var n = data_name.indexOf(temp[i].name);
        if (n == -1) {
          data_name.push(temp[i].name);
          data_seq.push(temp[i].seqno.seq);
          data_ses.push(temp[i].seqno.session);
        }
        else {
          data_seq[n] = temp[i].seqno.seq;
          data_ses[n] = temp[i].seqno.session;
        }
      }
    }
  }

  for(var i = 0; i < data_name.length; i++) {
    content[i] = new this.SyncState({ name:data_name[i],
                                 type:'UPDATE',
                                 seqno: {
                                   seq:data_seq[i],
                                   session:data_ses[i]
                                 }
                               });
  }
  if (content.length != 0) {
    var content_t = new this.SyncStateMsg({ss:content});
    var str = new Uint8Array(content_t.toArrayBuffer());
    var n = new Name(this.prefix)
    n.append(this.chatroom).append(syncdigest_t);

    var co = new Data(n);
    co.setContent(new Blob(str, false));
    this.keyChain.sign(co, this.certificateName, function() {
      try {
        face.putData(co);
      }
      catch (e) {
        console.log(e.toString());
      }
    });
  }
};

/**
 * Send recovery interset.
 * @param {string} syncdigest_t
 */
ChronoSync2013.prototype.sendRecovery = function(syncdigest_t)
{
  var n = new Name(this.applicationBroadcastPrefix);
  n.append("recovery").append(syncdigest_t);

  var interest = new Interest(n);

  interest.setInterestLifetimeMilliseconds(this.sync_lifetime);

  this.face.expressInterest(interest, this.onData.bind(this), this.syncTimeout.bind(this));
};

/**
 * This is called by onInterest after a timeout to check if a recovery is needed.
 * This method has an interest argument because we use it as the onTimeout for
 * Face.expressInterest.
 * @param {Interest}
 * @param {string}
 * @param {Face}
 */
ChronoSync2013.prototype.judgeRecovery = function(interest, syncdigest_t, face)
{
  //console.log("*** judgeRecovery interest " + interest.getName().toUri() + " times out. Digest: " + syncdigest_t + " ***");
  var index = this.logfind(syncdigest_t);
  if (index != -1) {
    if (syncdigest_t != this.digest_tree.root)
      this.processSyncInst(index, syncdigest_t, face);
  }
  else
    this.sendRecovery(syncdigest_t);
};

ChronoSync2013.prototype.syncTimeout = function(interest)
{
  if (!this.enabled)
    // Ignore callbacks after the application calls shutdown().
    return;

  var component = interest.getName().get
    (this.applicationBroadcastPrefix.size()).toEscapedString();
  if (component == this.digest_tree.root) {
    var n = new Name(interest.getName());
    var newInterest = new Interest(n);

    interest.setInterestLifetimeMilliseconds(this.sync_lifetime);
    this.face.expressInterest(newInterest, this.onData.bind(this), this.syncTimeout.bind(this));
  }
};

ChronoSync2013.prototype.initialOndata = function(content)
{
  this.update(content);

  var digest_t = this.digest_tree.getRoot();
  for (var i = 0; i < content.length; i++) {
    if (content[i].name == this.applicationDataPrefixUri && content[i].seqno.session == this.session) {
      //if the user was an old comer, after add the static log he need to increase his seqno by 1
      var content_t = [new this.SyncState({ name:this.applicationDataPrefixUri,
                                       type:'UPDATE',
                                       seqno: {
                                         seq:content[i].seqno.seq + 1,
                                         session:this.session
                                       }
                                     })];
      if (this.update(content_t)) {
        var newlog = new ChronoSync2013.DigestLogEntry(this.digest_tree.getRoot(), content_t);
        this.digest_log.push(newlog);
        try {
          this.onInitialized();
        } catch (ex) {
          console.log("Error in onInitialized: " + NdnCommon.getErrorWithStackTrace(ex));
        }
      }
    }
  }

  var content_t;
  if (this.usrseq >= 0) {
    //send the data packet with new seqno back
    content_t = new this.SyncState({ name:this.applicationDataPrefixUri,
                                   type:'UPDATE',
                                   seqno: {
                                     seq:this.usrseq,
                                     session:this.session
                                   }
                                 });
  }
  else
    content_t = new this.SyncState({ name:this.applicationDataPrefixUri,
                                   type:'UPDATE',
                                   seqno: {
                                     seq:0,
                                     session:this.session
                                   }
                                 });
  var content_tt = new this.SyncStateMsg({ss:content_t});
  this.broadcastSyncState(digest_t, content_tt);

  if (this.digest_tree.find(this.applicationDataPrefixUri, this.session) == -1) {
    //the user haven't put himself in the digest tree
    this.usrseq++;
    var content = [new this.SyncState({ name:this.applicationDataPrefixUri,
                                   type:'UPDATE',
                                   seqno: {
                                     seq:this.usrseq,
                                     session:this.session
                                   }
                                 })];
    if (this.update(content)) {
      try {
        this.onInitialized();
      } catch (ex) {
        console.log("Error in onInitialized: " + NdnCommon.getErrorWithStackTrace(ex));
      }
    }
  }
};

ChronoSync2013.prototype.dummyOnData = function(interest, data)
{
  console.log("*** dummyOnData called. ***");
};