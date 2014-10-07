/*
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Zhehao Wang
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

var ChronoChat = function(screenName, chatRoom, hubPrefix, face, keyChain, certificateName)
{
  this.screen_name = screenName;
  this.chatroom = chatRoom;
  this.maxmsgcachelength = 100;
  this.isRecoverySyncState = true;
  this.sync_lifetime = 5000.0;
  this.face = face;
  this.keyChain = keyChain;
  this.certificateName = certificateName;
  
  this.chat_prefix = (new Name(hubPrefix)).append(this.chatroom).append(this.getRandomString());
  this.roster = [];
  this.msgcache = [];
  
  var session = (new Date()).getTime();
  session = parseInt(session/1000);
  
  usrname = this.screen_name + session;
  
  if (this.screen_name == "" || this.chatroom == "") {
    console.log("input usrname and chatroom");
  }
  else {
    console.log(this.screen_name + ", welcome to chatroom " + this.chatroom + "!");
    this.sync = new ChronoSync2013(this.sendInterest.bind(this), this.initial.bind(this), this.chat_prefix, (new Name("/ndn/broadcast/ChronoChat-0.3")).append(this.chatroom), session, face, keyChain, certificateName, this.sync_lifetime, this.onRegisterFailed.bind(this));
    face.registerPrefix(this.chat_prefix, this.onInterest.bind(this), this.onRegisterFailed.bind(this));
  }
};

/**
 * Send the data packet which contains the user's message
 * @param {Name} Interest name prefix
 * @param {Interest} The interest
 * @param {Transport} The transport
 * @param {uint64_t} registerPrefixId 
 */
ChronoChat.prototype.onInterest = function(prefix, inst, transport, registerPrefixId)
{
  var content = {};
  // chat_prefix should really be saved as a name, not a URI string.
  var chatPrefixSize = new Name(chat_prefix).size();
  var seq = parseInt(inst.getName().get(chatPrefixSize + 1).getValue().buf().toString('binary'));
  for (var i = this.msgcache.length - 1 ; i >= 0; i--) {
    if (this.msgcache[i].seqno == seq) {
      if(this.msgcache[i].msgtype != 'CHAT')
        content = new ChatMessage({from:this.screen_name, to:this.chatroom, type:this.msgcache[i].msgtype, timestamp:this.msgcache[i].time/1000});
      else
        content = new ChatMessage({from:this.screen_name, to:this.chatroom, type:this.msgcache[i].msgtype, data:this.msgcache[i].msg, timestamp:this.msgcache[i].time/1000});
        break;
    }
  }
  if (content.from != null) {
    var str = new Uint8Array(content.toArrayBuffer());
    var co = new ContentObject(inst.getName(),str);
    co.sign();
    try {
      transport.send(co.wireEncode().buf());
      console.log(content);
    } 
    catch (e) {
      console.log(e.toString());
    }
  }
};

ChronoChat.prototype.onRegisterFailed = function()
{

};

ChronoChat.prototype.initial = function()
{
  // Set the heartbeat timeout using the Interest timeout mechanism. heartbeat() function
  // will call itself again after a timeout.
  
  // Here ndn-cpp's implementation differs a little from ChronoChat-js, finding out reasons
  var timeout = new Interest("/timeout");
  timeout.setInterestLifetimeMilliseconds(60000);
  this.face.expressInterest(timeout, this.dummyOnData, this.heartbeat.bind(this));
  
  if (this.roster.indexOf(this.usrname) == -1) {
    this.roster.push(this.usrname);
    
    // Announce join locally
    var d = new Date();
    var t = d.getTime();
    
    this.msgcache.push({seqno:this.sync.usrseq,msgtype:'JOIN',msg:'xxx',time:t});
    while (this.msgcache.length > this.maxmsgcachelength)
      this.msgcache.shift();
  }
};

/**
 * This onData is passed as onData for timeout interest in initial, which means it
 * should not be called under any circumstances.
 */
ChronoChat.prototype.dummyOnData = function()
{

};

/**
 * Send a Chat interest to fetch chat messages after the user gets the Sync data packet
 * @param {SyncStates[]} The array of sync states
 * @param {bool} if it's in recovery state
 */
ChronoChat.prototype.sendInterest = function(syncStates, isRecovery)
{
  this.isRecoverySyncState = isRecovery;
  
  var sendlist = [];
  var sessionlist = [];
  var seqlist = [];
  
  for (var j = 0; j < syncStates.length; j++) {
    // the judgment for syncStates type does not exist for ndn-cpp, figure out why
    if (syncStates[j].type == 0) {
      // Probably should not be using this split method, use name components instead,
      // as in ndn-cpp library
      var name_component = syncStates[j].name.split('/');
      var name_t = name_component[name_component.length-1];
      var session = syncStates[j].seqno.session;
      if (name_t != this.screen_name) {
        var index_n = sendlist.indexOf(syncStates[j].name);
        if(index_n != -1) {
          sessionlist[index_n] = session;
          seqlist[index_n] = syncStates[j].seqno.seq;
        }
        else {
          sendlist.push(syncStates[j].name);
          sessionlist.push(session);
          seqlist.push(syncStates[j].seqno.seq);
        }
      }
    } 
  }
  
  for (var i = 0; i < sendlist.length; i++) {
    var n = new Name(sendlist[i]+'/'+sessionlist[i]+'/'+seqlist[i]);
    var interest = new Interest(n);
    interest.setInterestLifetimeMilliseconds(this.sync_lifetime);
    
    this.face.expressInterest(interest, this.onData.bind(this), this.chatTimeout.bind(this));
  }
};

/**
 * Process the incoming data
 * @param {Interest} inst
 * @param {Data} co
 */
ChronoChat.prototype.onData = function(inst, co)
{
  var arr = new Uint8Array(co.getContent().size());
  arr.set(co.getContent().buf());
  var content = ChatMessage.decode(arr.buffer);
  
  var temp = (new Date()).getTime();
  if (temp - content.timestamp * 1000 < 120000) {
    var t = (new Date(content.timestamp*1000)).toLocaleTimeString();
    var name = content.from;
    
    // chat_prefix should really be saved as a name, not a URI string.
    var chatPrefixSize = new Name(this.chat_prefix).size();
    var prefix = co.getName().getPrefix(chatPrefixSize).toUri();
    
    var session = (co.getName().get(chatPrefixSize + 0).getValue().buf()).toString('binary');
    var seqno = (co.getName().get(chatPrefixSize + 1).getValue().buf()).toString('binary');
    var l = 0;
    
    //update roster
    while (l < this.roster.length) {
      var name_t = this.roster[l].substring(0,this.roster[l].length-10);
      var session_t = this.roster[l].substring(this.roster[l].length-10,this.roster[l].length);
      if (name != name_t && content.type != 2)
        l++;
      else{
        if(name == name_t && session > session_t){
          this.roster[l] = name+session;
        }
        break;
      }
    }
    
    if(l == this.roster.length) {
      this.roster.push(name + session);
      
      /*
      document.getElementById('txt').innerHTML += '<div><b><grey>'+name+'-'+t+': Join'+'</grey></b><br /></div>';
      var objDiv = document.getElementById("txt");      
      objDiv.scrollTop = objDiv.scrollHeight;
      document.getElementById('menu').innerHTML = '<p><b>Member</b></p><ul>';
      for(var i = 0;i < this.roster.length; i++){
        var name_t = this.roster[i].substring(0,this.roster[i].length-10);
        document.getElementById('menu').innerHTML += '<li>'+name_t+'</li>';
      }
      document.getElementById('menu').innerHTML += '</ul>';
      */
    }
    var self = this;
    setTimeout(function() {self.alive(seqno,name,session,prefix);},120000);
    
    if (content.type == 0 && sync.flag == 0 && content.from != screen_name){
      //display on the screen will not display old data
      /*
      var escaped_msg = $('<div/>').text(content.data).html();  // encode special html characters to avoid script injection
      document.getElementById('txt').innerHTML +='<p><grey>'+ content.from+'-'+t+':</grey><br />'+escaped_msg+'</p>';
      var objDiv = document.getElementById("txt");      
      objDiv.scrollTop = objDiv.scrollHeight;
      */
    }
    else if (content.type == 2) {
      //leave message
      var n = this.roster.indexOf(name + session);
      if(n != -1 && name != screen_name) {
        this.roster.splice(n,1);
        document.getElementById('menu').innerHTML = '<p><b>Member</b></p><ul>';
        for(var i = 0; i<this.roster.length; i++) {
          var name_t = this.roster[i].substring(0,this.roster[i].length-10);
          //document.getElementById('menu').innerHTML += '<li>'+name_t+'</li>';
        }
        //document.getElementById('menu').innerHTML += '</ul>';
        
        var d = new Date(content.timestamp*1000);
        var t = d.toLocaleTimeString();
        /*
        document.getElementById('txt').innerHTML += '<div><b><grey>'+name+'-'+t+': Leave</grey></b><br /></div>'
        var objDiv = document.getElementById("txt");      
        objDiv.scrollTop = objDiv.scrollHeight;
        */
      }
    }
  }
};

/**
 * No chat data coming back.
 * @param {Interest}
 */
ChronoChat.prototype.chatTimeout = function(interest)
{

};

/**
 *
 * @param {Interest}
 */
ChronoChat.prototype.heartbeat = function(interest)
{
  // based on ChronoChat-js's approach
  /*
  if (this.msgcache.length == 0){
    var d = new Date();
    var t = d.getTime();
    this.msgcache.push({seqno:sync.usrseq, msgtype:"JOIN", msg:"xxx", time:t});
  }
  
  sync.usrseq++;
  var content = [new SyncState({name:chat_prefix,type:'UPDATE',seqno:{seq:sync.usrseq,session:session}})];
  
  var d = new Date();
  var t = d.getTime();
  this.msgcache.push({seqno:sync.usrseq,msgtype:"HELLO",msg:"xxx",time:t});
  while (this.msgcache.length > this.maxmsgcachelength)
    this.msgcache.shift();
  var content_t = new SyncStateMsg({ss:content});
  var str = new Uint8Array(content_t.toArrayBuffer());
  var n = new Name(sync.prefix+chatroom+'/'+sync.digest_tree.root);
  var co = new ContentObject(n, str);
  co.sign();
  try {
    // poking is no longer enabled, should switch to memory content cache 
    pokeData(co);
  } catch (e) {
    console.log(e.toString());
  }
  this.sync.digest_tree.update(content,sync);
  if(sync.logfind(sync.digest_tree.root)==-1) {
    console.log("heartbeat log add");
    var newlog = {digest:sync.digest_tree.root, data:content};
    sync.digest_log.push(newlog);
    var n = new Name(sync.prefix+chatroom+'/'+sync.digest_tree.root);
    var template = new Interest();
    template.setInterestLifetimeMilliseconds(sync_lifetime);
    face.expressInterest(n, template, sync.onData.bind(sync), sync.syncTimeout.bind(sync));                
    console.log('Heartbeat Interest expressed.');
    console.log(n.toUri());
  } 
  */
  // Based on ndn-cpp library approach
  if (this.msgcache.length == 0) {
    // Announcing join; should use enum variable
    this.messageCacheAppend("JOIN", "xxx");
  }
  this.sync.publishNextSequenceNo();
  this.messageCacheAppend("HELLO", "xxx");
  
  // Making a timeout interest for heartbeat...
  var timeout = new Interest("/timeout");
  timeout.setInterestLifetimeMilliseconds(60000);
  this.face.expressInterest(timeout, this.dummyOnData, this.heartbeat.bind(this));
};

/**
 * This is called after a timeout to check if the user with prefix has a newer sequence
 * number than the given temp_seq. If not, assume the user is idle and remove from the
 * roster and print a leave message.
 * This method has an interest argument because we use it as the onTimeout for
 * Face.expressInterest.
 * @param {Interest}
 * @param {int}
 * @param {string}
 * @param {int}
 * @param {string}
 */
ChronoChat.prototype.alive = function(interest, temp_seq, name, session, prefix)
{
  console.log("check alive");
  var index_n = this.sync.digest_tree.find(prefix, session);
  var n = this.roster.indexOf(name + session);
  
  if (index_n != -1 && n != -1) {
    var seq = sync.digest_tree.digestnode[index_n].seqno.seq;
    if (temp_seq == seq) {
      this.roster.splice(n,1);
      console.log(name+" leave");
      var d = new Date();
      var t = d.toLocaleTimeString();
      // DOM handling
      /*
      document.getElementById('txt').innerHTML += '<div><b><grey>'+name+'-'+t+': Leave</grey></b><br /></div>'
      var objDiv = document.getElementById("txt");      
      objDiv.scrollTop = objDiv.scrollHeight;
      document.getElementById('menu').innerHTML = '<p><b>Member</b></p><ul>';
      for(var i = 0;i<this.roster.length;i++){
        var name_t = this.roster[i].substring(0,this.roster[i].length-10);
        document.getElementById('menu').innerHTML += '<li>'+name_t+'</li>';
      }
      document.getElementById('menu').innerHTML += '</ul>';
      */
    }
  }
};

/**
 * @param {string}
 */
ChronoChat.prototype.sendMessage = function(chatmsg)
{
  if (this.msgcache.length == 0)
    this.messageCacheAppend("JOIN", "xxx");
  if (chatmsg != "") {
    this.sync.publishNextSequenceNo();
    this.messageCacheAppend("CHAT", chatmsg);
    // Display chat message
  }
}

/**
 * Append a new CachedMessage to msgcache, using given messageType and message, 
 * the sequence number from this.sync.getSequenceNo() and the current time.
 * Also remove elements from the front of the cache as needed to keep the size to
 * this.maxmsgcachelength.
 */
ChronoChat.prototype.messageCacheAppend = function(messageType, message)
{
  var d = new Date();
  var t = d.getTime();
  this.msgcache.push({seqno:this.sync.usrseq, msgtype:messageType, msg:message, time:t});
  // ndn-cpp also has a remove mechanism, which removes those in the head when the length of cache is larger than max
  // this.msgcache.erase() does not seem to be a standard method?
};

// These are static functions; not sure if they should follow this pattern?
// Or should I remove prototype?

ChronoChat.prototype.onRegisterFailed = function()
{

};

ChronoChat.prototype.getRandomString = function()
{
  var seed = 'qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM0123456789';
  var result = '';
  for (var i = 0; i < 10; i++) {
    var pos = Math.floor(Math.random() * seed.length);
    result += seed[pos];
  }
  return result;
};

// Embedded class CachedMessage; defining class with its constructor
ChronoChat.CachedMessage = function (seqno, msgtype, msg, time)
{
  this.seqno = seqno;
  this.msgtype = msgtype;
  this.msg = msg;
  this.time = time;
};

ChronoChat.CachedMessage.prototype.getSequenceNo = function()
{
  return this.seqno;
};

ChronoChat.CachedMessage.prototype.getMessageType = function()
{
  return this.msgtype;
};

ChronoChat.CachedMessage.prototype.getMessage = function()
{
  return this.msg;
};

/**
 * @return MillisecondsSince1970
 */
ChronoChat.CachedMessage.prototype.getTime = function()
{
  return this.time;
};