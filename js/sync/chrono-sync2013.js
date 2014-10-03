/**
 * This class represents the digest tree for chrono-sync2013.
 * Copyright (C) 2013-2014 Regents of the University of California.
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
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var DigestTree = require('./digest-tree.js').DigestTree;
var Interest = require('../interest.js').Interest;
var Data = require('../data.js').Data;
var Name = require('../name.js').Name;
var Blob = require('../util/blob.js').Blob;
var MemoryContentCache = require('../util/memory-content-cache.js').MemoryContentCache;

// TODO: To use this, we require a SyncStateMsg declaration, 
// which exists in protobuf-js definition file.

var SyncStateMsg = require('./sync-state.js').SyncStateMsg;
var SyncState = require('./sync-state.js').SyncState;

/**
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
 * @param {function} onInitialized This calls onInitialized() when the first sync data
 * is received (or the interest times out because there are no other
 * publishers yet).
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
 */
var ChronoSync2013 = function ChronoSync2013(arg1, arg2, applicationDataPrefix, applicationBroadcastPrefix, sessionNo, face, keyChain, certificateName, syncLifetime, arg10)
{
  // assigning function pointers
  this.onReceivedSyncState = arg1;
  this.onInitialized = arg2;
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
  
  this.pendingInterestTable = [];
  
  this.digest_log = new Array();
  this.digest_log.push(new ChronoSync2013.DigestLogEntry("00",[]));
  
  this.contentCache.registerPrefix(this.applicationBroadcastPrefix, arg10.bind(this), this.onInterest.bind(this));
  
  var interest = new Interest(this.applicationBroadcastPrefix);
  interest.getName().append("00");
  
  interest.setInterestLifetimeMilliseconds(1000);
  interest.setAnswerOriginKind(Interest.ANSWER_NO_CONTENT_STORE);
  
  this.face.expressInterest(interest, this.onData.bind(this), this.initialTimeOut.bind(this));
};

exports.ChronoSync2013 = ChronoSync2013;

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
 */
ChronoSync2013.prototype.publishNextSequenceNo = function()
{
  this.usrseq ++;
  var content = [new SyncState({ name:this.applicationDataPrefixUri, 
                                 type:'UPDATE', 
                                 seqno:{
                                   seq:this.usrseq,
                                   session:this.session
                                  }
                                })];
  var content_t = new SyncStateMsg({ss:content});
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

// PendingInterest class

/**
 * A PendingInterest holds an interest which onInterest received but could
 * not satisfy. When we add a new data packet to this.contentCache, we will
 * also check if it satisfies a pending interest.
 */
ChronoSync2013.PendingInterest = function ChronoSync2013PendingInterest(interest, transport)
{
  this.interest = interest;
  this.transport = transport;
  
  if (this.interest.getInterestLifetimeMilliseconds() >= 0.0)
    this.timeoutMilliseconds = (new Date()).getTime() + this.interest.getInterestLifetimeMilliseconds();
  else
    this.timeoutMilliseconds = -1.0;
};

ChronoSync2013.PendingInterest.prototype.getInterest = function()
{
  return this.interest;
};

ChronoSync2013.PendingInterest.prototype.getTransport = function()
{
  return this.transport;
};

ChronoSync2013.PendingInterest.prototype.isTimedOut = function(nowMilliseconds)
{
  return (this.timeoutTimeMilliseconds >= 0.0 && nowMilliseconds >= this.timeoutTimeMilliseconds);
};

// Private methods for ChronoSync2013 class, 
/**
 * Make a data packet with the syncMessage and with name applicationBroadcastPrefix_ + digest.
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
  this.keyChain.sign(data, this.certificateName);
  this.contentCacheAdd(data);
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
      if (this.digest_tree.update(content[i].name, content[i].seqno.seq, content[i].seqno.session)) {
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
 * satisfy the interest, add it to the pendingInterestTable so that a future
 * call to contentCacheAdd may satisfy it.
 */
ChronoSync2013.prototype.onInterest = function(prefix, inst, transport, registerPrefixId)
{
  //search if the digest is already exist in the digest log
  
  var syncdigest = inst.getName().get(this.applicationBroadcastPrefix.size()).toEscapedString();
  if (inst.getName().size() == this.applicationBroadcastPrefix.size() + 2) {
    syncdigest = inst.getName().get(this.applicationBroadcastPrefix.size() + 1).toEscapedString();
  }
  if (inst.getName().size() == this.applicationBroadcastPrefix.size() + 2 || syncdigest == "00") {
    //Recovery interest or new comer interest
    //console.log("****** Parameter passed to processRecoveryInst: " + syncdigest + " ******");
    this.processRecoveryInst(inst, syncdigest, transport);
  }
  else {
    this.pendingInterestTable.push(new ChronoSync2013.PendingInterest(inst, transport));
    
    if (syncdigest != this.digest_tree.getRoot()) {
      var index = this.logfind(syncdigest);
      var content = [];
      if(index == -1) {
        var self = this;
        // Are we sure that using a "/timeout" interest is the best future call approach?
        var timeout = new Interest(new Name("/timeout"));
        timeout.setInterestLifetimeMilliseconds(2000);
        this.face.expressInterest(timeout, this.dummyOnData, this.judgeRecovery.bind(this, timeout, syncdigest, transport));
      }
      else {
        //common interest processing
        this.processSyncInst(index, syncdigest, transport);
      }
    }
  }
};

/**
 * Process sync/recovery data.
 * @param {Interest}
 * @param {Data}
 */
ChronoSync2013.prototype.onData = function(inst, co)
{
  var arr = new Uint8Array(co.getContent().size());
  arr.set(co.getContent().buf());
  var content_t = SyncStateMsg.decode(arr.buffer);
  var content = content_t.ss;
  
  var isRecovery = false;
  
  if (this.digest_tree.getRoot() == "00") {
    isRecovery = true;
    this.initialOndata(content);
  }
  else {
    // Note: if, for some reasons, this update did not update anything, 
    // then the same message gets fetched again, and the same broadcast interest goes out again.
    // It has the potential of creating loop, which existed in my tests.
    if (inst.getName().size() == this.applicationBroadcastPrefix.size() + 2)
      isRecovery = false;
    else
      isRecovery = true;
  }
  
  var syncStates = [];

  for (var i = 0; i < content.length; i++) {
	if (content[i].type == 0) {
	  syncStates.push(new SyncState({ name:content[i].name,
									  type:'UPDATE',
									  seqno: {
										seq:content[i].seqno.seq,
										session:content[i].seqno.session
									  }
									}));
	}
  }

  this.onReceivedSyncState(syncStates, isRecovery);
  var updated = this.update(content);
  
  if (updated) {
	var n = new Name(this.applicationBroadcastPrefix);
	n.append(this.digest_tree.getRoot());
  
	var interest = new Interest(n);
	interest.setInterestLifetimeMilliseconds(this.sync_lifetime);
  
	this.face.expressInterest(interest, this.onData.bind(this), this.syncTimeout.bind(this));
  }
};

/**
 * Interest variable not actually in use here
 */
ChronoSync2013.prototype.initialTimeOut = function(interest)
{
  console.log("no other people");
    
  this.usrseq++;
  this.onInitialized();
  var content = [new SyncState({ name:this.applicationDataPrefixUri,
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

ChronoSync2013.prototype.processRecoveryInst = function(inst, syncdigest, transport)
{
  if (this.logfind(syncdigest) != -1) {
    var content = [];
    
    for(var i = 0; i < this.digest_tree.digestnode.length; i++) {
      content[i] = new SyncState({ name:this.digest_tree.digestnode[i].getDataPrefix(),
                                   type:'UPDATE',
                                   seqno:{
                                     seq:this.digest_tree.digestnode[i].getSequenceNo(),
                                     session:this.digest_tree.digestnode[i].getSessionNo()
                                    }
                                 });
    }
    
    if (content.length != 0) {
      var content_t = new SyncStateMsg({ss:content});
      var str = new Uint8Array(content_t.toArrayBuffer());
      var co = new Data(inst.getName());
      co.setContent(new Blob(str, false));
      this.keyChain.sign(co, this.certificateName);
      try {
        transport.send(co.wireEncode().buf());
      } catch (e) {
        console.log(e.toString());
      }
    }
  }
};

/**
 * Common interest processing, using digest log to find the difference after syncdigest_t
 * @return True if sent a data packet to satisfy the interest.
 */
ChronoSync2013.prototype.processSyncInst = function(index, syncdigest_t, transport)
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
        if (n = -1) {
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
    content[i] = new SyncState({ name:data_name[i],
                                 type:'UPDATE',
                                 seqno: {
                                   seq:data_seq[i],
                                   session:data_ses[i]
                                 }
                               });
  }
  if (content.length != 0) {
    var content_t = new SyncStateMsg({ss:content});
    var str = new Uint8Array(content_t.toArrayBuffer());
    var n = new Name(this.prefix)
    n.append(this.chatroom).append(syncdigest_t);
    
    var co = new Data(n);
    co.setContent(new Blob(str, false));
    this.keyChain.sign(co, this.certificateName);
    try {
      transport.send(co.wireEncode().buf());
    }
    catch (e) {
      console.log(e.toString());
    }
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

/*
 * This is called by onInterest after a timeout to check if a recovery is needed.
 * This method has an interest argument because we use it as the onTimeout for
 * Face.expressInterest.
 * @param {Interest}
 * @param {string}
 * @param {Transport}
 */
ChronoSync2013.prototype.judgeRecovery = function(interest, syncdigest_t, transport)
{
  //console.log("*** judgeRecovery interest " + interest.getName().toUri() + " times out. Digest: " + syncdigest_t + " ***");
  var index = this.logfind(syncdigest_t);
  if (index != -1) {
    if (syncdigest_t != this.digest_tree.root)
      this.processSyncInst(index, syncdigest_t, transport);
  }
  else
    this.sendRecovery(syncdigest_t);
};

ChronoSync2013.prototype.syncTimeout = function(interest)
{
  var component = interest.getName().get(4).toEscapedString();
  if (component == this.digest_tree.root) {
    var n = new Name(interest.getName());
    var interest = new Interest(n);
    
    interest.setInterestLifetimeMilliseconds(this.sync_lifetime);
    this.face.expressInterest(interest, this.onData.bind(this), this.syncTimeout.bind(this));
  }           
};

ChronoSync2013.prototype.initialOndata = function(content)
{
  this.update(content);
    
  var digest_t = this.digest_tree.getRoot();
  for (var i = 0; i < content.length; i++) {
    if (content[i].name == this.applicationDataPrefixUri && content[i].seqno.session == this.session) {
      //if the user was an old comer, after add the static log he need to increase his seqno by 1
      var content_t = [new SyncState({ name:this.applicationDataPrefixUri,
                                       type:'UPDATE',
                                       seqno: {
                                         seq:content[i].seqno.seq + 1,
                                         session:this.session
                                       }
                                     })];
      if (this.update(content_t)) {
        var newlog = new ChronoSync2013.DigestLogEntry(this.digest_tree.getRoot(), content_t);
        this.digest_log.push(newlog);
        this.onInitialized();
      }
    }
  }
  
  var content_t;
  if (this.usrseq >= 0) {
    //send the data packet with new seqno back
    content_t = new SyncState({ name:this.applicationDataPrefixUri,
                                   type:'UPDATE',
                                   seqno: { 
                                     seq:this.usrseq,
                                     session:this.session
                                   }
                                 });
  }
  else
    content_t = new SyncState({ name:this.applicationDataPrefixUri,
                                   type:'UPDATE',
                                   seqno: {
                                     seq:0,
                                     session:this.session
                                   }
                                 });
  var content_tt = new SyncStateMsg({ss:content_t});
  this.broadcastSyncState(digest_t, content_tt);
  
  if (this.digest_tree.find(this.applicationDataPrefixUri, this.session) == -1) {
    //the user haven't put himself in the digest tree
    this.usrseq++;
    var content = [new SyncState({ name:this.applicationDataPrefixUri,
                                   type:'UPDATE',
                                   seqno: { 
                                     seq:this.usrseq,
                                     session:this.session
                                   }
                                 })];
    if (this.update(content)) {
      this.onInitialized();
    }
  }
};

ChronoSync2013.prototype.contentCacheAdd = function(data)
{
  this.contentCache.add(data);
  
  var nowMilliseconds = (new Date()).getTime();
  
  for (var i = this.pendingInterestTable.length - 1; i >= 0; i--) {
    if (this.pendingInterestTable[i].isTimedOut(nowMilliseconds)) {
      this.pendingInterestTable.splice(i,1);
      continue;
    }
    if (this.pendingInterestTable[i].getInterest().matchesName(data.getName())) {
      try {
        this.pendingInterestTable[i].getTransport().send(data.wireEncode().buf());
      }
      catch (e) {
      }
      this.pendingInterestTable.splice(i,1);
    }
  }
};

ChronoSync2013.prototype.dummyOnData = function(interest, data)
{
  console.log("*** dummyOnData called. ***");
};