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
var Name = require('../name.js').Name;
var MemoryContentCache = require('../util/memory-content-cache.js').MemoryContentCache;

// TODO: To actually use this part of the library, we require a SyncStateMsg declaration,
// which exists in protobuf-js definition file. This could/should be made independent of
// the library...
var SyncStateMsg = require('./sync-state.js').SyncStateMsg;
var SyncState = require('./sync-state.js').SyncState;
//console.log("Imported results : " + SyncStateMsg);

// TODO: the equivalent of function pointers, or are there no such things?
// The point of naming it as 'argn'? just to correspond with boost::bind?
// Assuming that it takes the form of (OnReceivedSyncState, OnInitialized, 
// applicationDataPrefix, applicationBroadcastPrefix, sessionNo, face, 
// keyChain, certificateName, syncLifetime, onRegisterFailed)
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
  this.userseq = -1;
  
  this.digest_tree = new DigestTree();
  this.contentCache = new MemoryContentCache(face);

  this.digest_log = new Array();
  this.digest_log.push({digest:"00",data:[]});
  
  // Do I need prototype.bind for callback functions? Supposedly that I do
  // contentCache is a memoryContentCache, not an ordinary face.
  // Debug memoryContentCaches
  this.contentCache.registerPrefix(this.applicationBroadcastPrefix, arg10.bind(this), this.onInterest.bind(this));
  
  var interest = new Interest(this.applicationBroadcastPrefix);
  interest.getName().append("00");
  
  interest.setInterestLifetimeMilliseconds(1000);
  interest.setAnswerOriginKind(Interest.ANSWER_NO_CONTENT_STORE);
  
  // The same wonder of using bind applies here, too
  this.face.expressInterest(interest, this.onData.bind(this), this.initialTimeOut.bind(this));
};

exports.ChronoSync2013 = ChronoSync2013;

// SyncState class: its declaration exists in ProtoBuf file.
// This class could be re-enabled after we remove our reference to protobuf in this library
// file. Its function/info should be the same for this class and protobuf definition,
// calling methods may change after using this class.
/*
ChronoSync2013.SyncState = function ChronoSync2013SyncState(dataPrefixUri, sessionNo, sequenceNo)
{
  this.dataPrefixUri = dataPrefixUri;
  this.sessionNo = sessionNo;
  this.sequenceNo = sequenceNo;
};

ChronoSync2013.SyncState.prototype.getDataPrefix = function()
{
  return this.dataPrefixUri;
};

ChronoSync2013.SyncState.prototype.getSessionNo = function()
{
  return this.sessionNo;
};

ChronoSync2013.SyncState.prototype.getSequenceNo = function()
{
  return this.sequenceNo;
};
*/

ChronoSync2013.prototype.getProducerSequenceNo = function(dataPrefix, sessionNo)
{
  var index = this.digest_tree.find(dataPrefix, sessionNo);
  if (index < 0) 
    return -1;
  else
    return this.digest_tree.get(index).getSequenceNo();
};

ChronoSync2013.prototype.publishNextSequenceNo = function()
{
  this.usrseq ++;
  //var content_t = new SyncStateMsg({ss:content});
  var content = [new SyncState({name:this.applicationDataPrefixUri,type:'UPDATE',seqno:{seq:this.usrseq,session:this.session}})];
  
  // broadcastSyncState not yet implemented
  this.broadcastSyncState(this.digest_tree.getRoot(), content);
  
  // New digest log entry judgment neglected here for now
  
  var interest = new Interest(this.applicationBroadcastPrefix);
  interest.getName().append(this.digest_tree.getRoot());
  interest.setInterestLifetimeMilliseconds(this.sync_lifetime);
  
  this.face.expressInterest(interest, this.onData.bind(this), this.syncTimeout.bind(this));
};

ChronoSync2013.prototype.getSequenceNo = function()
{
  return this.usrseq;
};

// DigestLogEntry class

ChronoSync2013.DigestLogEntry = function ChronoSync2013DisgestLogEntry(digest, data)
{
  this.digest = digest;
  // Not sure if data still follows the intended semantics as in ndn-cpp
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

ChronoSync2013.PendingInterest = function ChronoSync2013PendingInterest(interest, transport)
{
  this.interest = interest;
  this.transport = transport;
  
  // TODO: getNowMilliseconds is an ndn utility function, and the library it belongs to is not yet added
  if (this.interest.getInterestLifetimeMilliseconds() >= 0.0)
    this.timeoutMilliseconds = getNowMilliseconds() + this.interest.getInterestLifetimeMilliseconds();
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

// Private methods for ChronoSync2013 class, TODO: fill implementation and comments into the skeleton.

ChronoSync2013.prototype.broadcastSyncState = function(digest, syncMessage)
{
  
};

/**
 * Update the digest tree with the messages in content. If the digest tree root is not in
 * the digest log, also add a log entry with the content.
 * @param {SyncStates[]} The sync state messages
 * @return {bool} True if added a digest log entry (because the updated digest tree root
 * was not in the log), false if didn't add a log entry.
 */
ChronoSync2013.prototype.update = function(content)
{
  for (var i = 0; i < content.length; i++) {
    if (content[i].type == 0) {
      if (this.digest_tree.update(content[i].name, content[i].seqno.session, content[i].seqno.seq)) {
        if (this.applicationDataPrefixUri == content[i].name)
          this.usrseq = content[i].seqno.seq;
      }
    }
  
    if (this.logfind(this.digest_tree.getRoot()) == -1) {
      var newlog = {digest:this.digest_tree.getRoot(), data:content};
      this.digest_log.push(newlog);
      return true;
    }
    else {
      return false;
    }
  }
};

ChronoSync2013.prototype.logfind = function(digest)
{
  for (var i = 0; i<this.digest_log.length; i++) {
    if(digest == this.digest_log[i].digest)
      return i;
  }
  return -1;
};

// registerPrefixId is not used in this function
ChronoSync2013.prototype.onInterest = function(prefix, inst, transport, registerPrefixId)
{
  //search if the digest is already exist in the digest log
  console.log('Sync Interest received in callback.');
  
  // DataUtil is a part of ndn.js, which is not included in this file; its toString method removed; 
  // and the logic is confusing; size vs length in here, double check the type of applicationBroadcastPrefix?
  var syncdigest = inst.getName().get(this.applicationBroadcastPrefix.size()).toEscapedString();
  console.log(syncdigest);
  if (inst.getName().size() == this.applicationBroadcastPrefix.size() + 2) {
    syncdigest = inst.getName().get(this.applicationBroadcastPrefix.size() + 1).toEscapedString();
  }
  if (inst.getName().size() == this.applicationBroadcastPrefix.size() + 2 || syncdigest == "00") {
    //Recovery interest or new comer interest
    this.processRecoveryInst(inst, syncdigest, transport);
  }
  else {
    // Should save interest in local PIT, which is not yet implemented.
    if (syncdigest != this.digest_tree.root) {
      var index = this.logfind(syncdigest);
      var content = [];
      if(index == -1) {
        var self = this;
        //Wait 2 seconds to see whether there is any data packet coming back
        setTimeout(function(){self.judgeRecovery(syncdigest, transport);},2000);
        console.log("set timer recover");
      }
      else {
        //common interest processing
        this.processSyncInst(index,syncdigest, transport);
      }
    }
  }
};

ChronoSync2013.prototype.onData = function(inst, co)
{
  console.log("Sync ContentObject received in callback");
  console.log('name:'+co.getName().toUri());
  
  var arr = new Uint8Array(co.getContent().size());
  arr.set(co.getContent().buf());
  var content_t = Sync.SyncStateMsg.decode(arr.buffer);
  var content = content_t.ss;
  
  var isRecovery = false;
  
  if(this.digest_tree.root == "00") {
    isRecovery = true;
    //processing initial sync data
    this.initialOndata(content);
  }
  else {
    
    // this part seems to equal with ChronoSync2013::update
    this.digest_tree.update(content,this);
    if (this.logfind(this.digest_tree.root) == -1) {
      var newlog = {digest:this.digest_tree.root, data:content};
      this.digest_log.push(newlog);
    }
    // equality ends
    
    if (inst.getName().size() == this.applicationBroadcastPrefix.size() + 2)
      isRecovery = false;
    else
      isRecovery = true;
  }
  
  // Send the interests to fetch application data; this is what actually get executed
  console.log(content);
  
  var syncStates = [];
  
  // Original logic for reporting UPDATE sync states
  /*
  var sendlist = [];
  var sessionlist = [];
  var seqlist = [];
  
  for( var j = 0; j < content.length; j++) {
    if(content[j].type == 0){
      var name_component = content[j].name.split('/');
      var name_t = name_component[name_component.length-1];
      var session = content[j].seqno.session;
      if (name_t != screen_name) {
        var index_n = sendlist.indexOf(content[j].name);
        if(index_n != -1) {
          sessionlist[index_n] = session;
          seqlist[index_n] = content[j].seqno.seq;
        }
        else {
          sendlist.push(content[j].name);
          sessionlist.push(session);
          seqlist.push(content[j].seqno.seq);
        }
      }
    }
  }
  */
  
  for (var i = 0; i < content.length; i++) {
    if (content[i].type == 0) {
      // Constructor syntactical check
      syncStates.push(new SyncState(content[i].name, content[i].seqno.session, content[i].seqno.seq));
    }
  }
  
  // The equivalent of syncStates seems to be the summary of the three lists mentioned above
  // TODO: implementation of syncStates
  this.onReceivedSyncState(syncStates, isRecovery);
  
  /*
  for (var i = 0; i < sendlist.length; i++) {
    var n = new Name(sendlist[i]+'/'+sessionlist[i]+'/'+seqlist[i]);
    var template = new Interest();
    template.setInterestLifetimeMilliseconds(sync_lifetime);
    this.face.expressInterest(n, template, this.onData.bind(this), this.chatTimeout.bind(this));
    
    console.log(n.toUri());
    console.log('Chat Interest expressed.');
  }
  */
  
  var n = new Name(this.applicationBroadcastPrefix);
  var interest = new Interest(n);
  interest.setInterestLifetimeMilliseconds(this.sync_lifetime);
  this.face.expressInterest(interest, this.onData.bind(this), this.syncTimeout.bind(this));
  
  console.log("Sync interest expressed:");
  console.log(n.toUri());
};

/**
 * Interest variable not actually in use here
 */
ChronoSync2013.prototype.initialTimeOut = function(interest)
{
  console.log("initial sync timeout");
  console.log("no other people");
    
  // Digest tree initialization not yet implemented
  // Interestingly, ndn-cpp does not have digest tree initial, wonder how it creates the
  // first node of the local instance.
  //this.digest_tree.initial(this);
  
  this.usrseq++;
  // usrseq should be 0 after the increment.
  // chat::initial is passed in here, which is the heartbeat mechanism using timeouts
  this.onInitialized();
  
  // Content should be array of SyncStates.
  var content = [new SyncState({ name:this.applicationDataPrefixUri,
                                                type:'UPDATE',
                                                seqno: {
                                                  seq:this.usrseq,
                                                  session:this.session
                                                }
                                              })];
  // This update puts the local node into digest tree.
  this.update(content);
  
  var n = new Name(this.applicationBroadcastPrefix);
  n.append(this.digest_tree.getRoot());
  var retryInterest = new Interest(n);
  retryInterest.setInterestLifetimeMilliseconds(this.sync_lifetime);
  this.face.expressInterest(retryInterest, this.onData.bind(this), this.syncTimeout.bind(this));
  
  console.log("Sync interest expressed:");
  console.log(n.toUri());
};

ChronoSync2013.prototype.processRecoveryInst = function(inst, syncdigest, transport)
{
  if (this.logfind(syncdigest) != -1) {
    var content = [];
    // If nothing's found in log, do nothing.
    console.log(" *** log found *** " + this.digest_tree.digestnode.length);
    for(var i = 0; i < this.digest_tree.digestnode.length; i++) {
      content[i] = new SyncState({ name:this.digest_tree.digestnode[i].prefix_name,
                                                  type:'UPDATE',
                                                  seqno:{
                                                    seq:this.digest_tree.digestnode[i].seqno.seq,
                                                    session:this.digest_tree.digestnode[i].
                                                    seqno.session
                                                  }
                                                });
    }
    if (content.length != 0) {
      var content_t = new SyncStateMsg({ss:content});
      var str = new Uint8Array(content_t.toArrayBuffer());
      var co = new ContentObject(inst.getName(), str);
      co.sign();
      try {
        transport.send(co.wireEncode().buf());
        console.log("send recovery data back");
        console.log(inst.getName().toUri());
      } catch (e) {
        console.log(e.toString());
      }
    }
  }
};

ChronoSync2013.prototype.processSyncInst = function(index, syncdigest_t, transport)
{
  var content = [];
  var data_name = [];
  var data_seq = [];
  var data_ses = [];

  for (var j = index+1; j < this.digest_log.length; j++) {
    var temp = this.digest_log[j].data;
    for (var i = 0 ; i<temp.length ; i++) {
      if (temp[i].type != 0) {
        continue;
      }
      if (this.digest_tree.find(temp[i].name, temp[i].seqno.session) != -1) {
        var n = data_name.indexOf(temp[i].name);
        if(n = -1) {
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
    content[i] = new SyncState({name:data_name[i], type:'UPDATE', seqno:{seq:data_seq[i],session:data_ses[i]}});
  }
  if(content.length != 0) {
    var content_t = new SyncStateMsg({ss:content});
    var str = new Uint8Array(content_t.toArrayBuffer());
    var n = new Name(this.prefix+this.chatroom+'/'+syncdigest_t);
    var co = new ContentObject(n, str);
    co.sign();
    try {
      transport.send(co.wireEncode().buf());
      console.log("Sync Data send");
      console.log(n.toUri());
    } catch (e) {
      console.log(e.toString());
    }
  }
};

ChronoSync2013.prototype.sendRecovery = function(syncdigest_t)
{
  console.log("unknown digest: ")
  var n = new Name(this.applicationBroadcastPrefix + '/recovery/' + syncdigest_t);
  var interest = new Interest(n);

  n.setInterestLifetimeMilliseconds(this.sync_lifetime);
  this.face.expressInterest(n, this.onData.bind(this), this.syncTimeout.bind(this));
  
  console.log("Recovery Syncinterest expressed:"); 
  console.log(n.toUri());
};

ChronoSync2013.prototype.judgeRecovery = function(interest, syncdigest_t, transport)
{
  var index2 = this.logfind(syncdigest_t);
  if (index2 != -1) {
    if (syncdigest_t != this.digest_tree.root)
      this.processSyncInst(index2,syncdigest_t, transport);
  }
  else
    this.sendRecovery(syncdigest_t);
};

ChronoSync2013.prototype.syncTimeout = function(interest)
{
  console.log("Sync Interest time out.");
  console.log('Sync Interest name: ' + interest.getName().toUri());

  // The fifth(4) component should be replaced by some consts
  var component = (interest.getName().get(4).getValue().buf()).toString('binary');
  if (component == this.digest_tree.root) {
    var n = new Name(interest.getName());
    var interest = new Interest(n);
    
    interest.setInterestLifetimeMilliseconds(this.sync_lifetime);
    this.face.expressInterest(interest, this.onData.bind(this), this.syncTimeout.bind(this));
    
    console.log("Sync interest expressed:");
    console.log(n.toUri());
  }           
};

ChronoSync2013.prototype.initialOndata = function(content)
{
  //user is a new comer and receive data of all other people in the group
  this.digest_tree.update(content, this);
  
  if (this.logfind(this.digest_tree.getRoot()) == -1) {
    var newlog = {digest:this.digest_tree.root, data:content};
    this.digest_log.push(newlog);
  }
    
  var digest_t = this.digest_tree.root;
  for (var i = 0; i < content.length; i++) {
    if (content[i].name == this.applicationDataPrefixUri && content[i].seqno.session == this.session) {
      //if the user was an olde comer, after add the static log he need to increase his seqno by 1
      var content_t = [new SyncState({name:this.applicationDataPrefixUri,type:'UPDATE',seqno:{seq:content[i].seqno.seq+1,session:this.session}})];
      this.digest_tree.update(content_t,this);
      if (this.logfind(this.digest_tree.getRoot()) == -1) {
        var newlog = {digest:this.digest_tree.getRoot(), data:content_t};
        this.digest_log.push(newlog);
        
        // Not sure if it's the right way to call a function pointer passed from constructor
        this.onInitialized();
      }
    }
  }

  var content_t =[]
  if (this.usrseq >= 0) {
    //send the data packet with new seqno back
    content_t[0] = new SyncState({name:this.applicationDataPrefixUri,type:'UPDATE',seqno:{seq:this.usrseq,session:this.session}});
  }
  else
    content_t[0] = new SyncState({name:this.applicationDataPrefixUri,type:'UPDATE',seqno:{seq:0,session:this.session}});
  
  var content_tt = new SyncStateMsg({ss:content_t});
  var str = new Uint8Array(content_tt.toArrayBuffer());
  var n = new Name(this.prefix+this.chatroom+'/'+digest_t);
  var co = new ContentObject(n, str);
  
  co.sign();
  console.log("initial update data sending back");
  console.log(n.toUri());
  
  // pokingData should be replaced
  try {
    pokeData(co);
  } catch (e) {
    console.log(e.toString());
  }
  
  if (this.digest_tree.find(this.applicationDataPrefixUri, this.session) == -1) {
    //the user haven't put himself in the digest tree
    console.log("initial state")
    this.usrseq++;
    var content = [new SyncState({name:this.applicationDataPrefixUri,type:'UPDATE',seqno:{seq:this.usrseq,session:this.session}})];
    this.digest_tree.update(content,this);
    if (this.logfind(this.digest_tree.root) == -1) {
      var newlog = {digest:this.digest_tree.root, data:content};
      this.digest_log.push(newlog);
      
      // Not sure if it's the right way to call a function pointer
      this.onInitialized();
    }
  }
};

ChronoSync2013.prototype.contentCacheAdd = function(data)
{
  
};

ChronoSync2013.prototype.dummyOnData = function(interest, data)
{

};