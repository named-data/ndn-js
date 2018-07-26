/*
 * Copyright (C) 2014-2017 Regents of the University of California.
 * @author: Zhehao Wang
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

var ChronoChat = function(screenName, chatRoom, rootPrefix, chat, face, syncDoc, keyChain, certificateName)
{
  this.screen_name = screenName;
  this.chatroom = chatRoom;
  this.maxmsgcachelength = 10000;
  this.isRecoverySyncState = true;
  this.sync_lifetime = 5000.0;
  this.face = face;
  this.keyChain = keyChain;
  this.certificateName = certificateName;
  this.fetchedHistorical = false;

  this.chat_prefix = (new Name(rootPrefix)).append(this.chatroom)
    .append(screenName);

  /*this.roster = [screenName];
  document.getElementById('menu').innerHTML = '<p><b>Member</b></p><ul><li>' + screenName + '</li></ul>';*/
  this.msgcache = [];
  this.roster = [];

  //console.log("The local chat prefix " + this.chat_prefix.toUri() + " ***");

  /* TODO: Do we need session numbers?
  var session = (new Date()).getTime();
  session = parseInt(session/1000);
  */
  var session = 0;

  this.usrname = this.screen_name + session;
  this.ChatMessage = SyncDemo.ChatMessage;

  if (this.screen_name == "" || this.chatroom == "") {
    console.log("input usrname and chatroom");
  }
  else {
    this.sync = new FireflySync(face.db_,
      syncDoc,
      this.chat_prefix.toUri(),
      this.initial.bind(this),
      this.sendInterest.bind(this));
    face.registerPrefix
      (this.chat_prefix, this.onInterest.bind(this),
       this.onRegisterFailed.bind(this));
  }
};

/**
 * Send the data packet which contains the user's message
 * @param {Name} Interest name prefix
 * @param {Interest} The interest
 * @param {Face} The face
 * @param {number} interestFilterId
 * @param {InterestFilter} filter
 */
ChronoChat.prototype.onInterest = function
  (prefix, interest, face, interestFilterId, filter)
{
  var content = {};

  // chat_prefix should really be saved as a name, not a URI string.
  var chatPrefixSize = new Name(this.chat_prefix).size();
  var seq = parseInt(interest.getName().get(chatPrefixSize + 1).toEscapedString());
  for (var i = this.msgcache.length - 1 ; i >= 0; i--) {
    if (this.msgcache[i].seqno == seq) {
      if(this.msgcache[i].msgtype != 'CHAT')
        content = new this.ChatMessage({from:this.screen_name, to:this.chatroom, type:this.msgcache[i].msgtype, timestamp:parseInt(this.msgcache[i].time/1000)});
      else
        content = new this.ChatMessage({from:this.screen_name, to:this.chatroom, type:this.msgcache[i].msgtype, data:this.msgcache[i].msg, timestamp:parseInt(this.msgcache[i].time/1000)});
      break;
    }
  }

  if (content.from != null) {
    var str = new Uint8Array(content.toArrayBuffer());
    var co = new Data(interest.getName());
    co.setContent(str);
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

ChronoChat.prototype.onRegisterFailed = function(prefix)
{
};

ChronoChat.prototype.initial = function()
{
  // fetch historical data
  var self = this;

  this.sync.getHistoricalDeltas(function(deltas){
    if (LOG > 0) console.log('got historical deltas')
    if (deltas.length)
      deltas.forEach(function(delta, idx, arr){
        for (var key in delta)
        {
          var decodedKey = decodeURIComponent(key);
          var uri = decodedKey+'/0/'+delta[key]; // beware! session number is hardcoded as zero here!!
          var interest = new Interest(new Name(uri));
          interest.setInterestLifetimeMilliseconds(self.sync_lifetime);

          if (LOG > 0) console.log('expressing interest for historical data ', interest.getName().toUri());
          self.face.expressInterest(interest, self.onData.bind(self), self.chatTimeout.bind(self));
        }

        if (idx == arr.length-1)
        {
          self.fetchedHistorical = true;
          if (LOG > 0) console.log('requested all historical ',self.fetchedHistorical);
        }
      });
    else
      self.fetchedHistorical = true;
  });

  /*var timeout = new Interest(new Name("/timeout"));
  timeout.setInterestLifetimeMilliseconds(60000);

  //TODO: figure out how to do the heartbeat
  this.face.expressInterest(timeout, this.dummyOnData, this.heartbeat.bind(this));*/

  if (this.roster.indexOf(this.usrname) == -1) {
    this.roster.push(this.usrname);

    document.getElementById('menu').innerHTML = '<p><b>Member</b></p>';
    document.getElementById('menu').innerHTML += '<ul><li>' + this.screen_name +
      '</li></ul>';
    var d = new Date();
    document.getElementById('txt').innerHTML += '<div><b><grey>' +
      this.screen_name + '-' + d.toLocaleTimeString() +
      ': Join</grey></b><br /></div>'
    var objDiv = document.getElementById("txt");
    objDiv.scrollTop = objDiv.scrollHeight;

    this.sync.publishNextSequenceNo();
    this.messageCacheAppend('JOIN', 'xxx');
  }
};

/**
 * This onData is passed as onData for timeout interest in initial, which means it
 * should not be called under any circumstances.
 */
ChronoChat.prototype.dummyOnData = function(interest, co)
{
  console.log("*** dummyOndata called, name: " + interest.getName().toUri() + " ***");
};

/**
 * Send a Chat interest to fetch chat messages after the user gets the Sync data packet
 * @param {SyncStates[]} The array of sync states
 * @param {bool} if it's in recovery state
 */
ChronoChat.prototype.sendInterest = function(syncStates, isRecovery)
{
  this.isRecoverySyncState = isRecovery;

  // this one is to prevent chronochat from retrieving latest data which
  // should be fetched as part of initial historical retrieval
  if (!this.fetchedHistorical)
  {
    if (LOG > 0) console.log('hasnt fetched historical yet ', this.fetchedHistorical);
    return;
  }

  var sendList = [];       // of String
  var sessionNoList = [];  // of number
  var sequenceNoList = []; // of number

  for (var j = 0; j < syncStates.length; j++) {
    var syncState = syncStates[j];
    var nameComponents = new Name(syncState.getDataPrefix());
    var tempName = nameComponents.get(-1).toEscapedString();
    var sessionNo = syncState.getSessionNo();
    if (tempName != this.screen_name) {
      var index = -1;
      for (var k = 0; k < sendList.length; ++k) {
        if (sendList[k] == syncState.getDataPrefix()) {
          index = k;
          break;
        }
      }
      if (index != -1) {
        sessionNoList[index] = sessionNo;
        sequenceNoList[index] = syncState.getSequenceNo();
      }
      else {
        sendList.push(syncState.getDataPrefix());
        sessionNoList.push(sessionNo);
        sequenceNoList.push(syncState.getSequenceNo());
      }
    }
  }

  for (var i = 0; i < sendList.length; ++i) {
    var uri = sendList[i] + "/" + sessionNoList[i] + "/" + sequenceNoList[i];
    var interest = new Interest(new Name(uri));
    interest.setInterestLifetimeMilliseconds(this.sync_lifetime);

    if (LOG > 0) console.log('expressing interest for data ', interest.getName().toUri());
    this.face.expressInterest(interest, this.onData.bind(this), this.chatTimeout.bind(this));
  }
};

/**
 * Process the incoming data
 * @param {Interest} interest
 * @param {Data} co
 */
ChronoChat.prototype.onData = function(interest, co)
{
  var arr = new Uint8Array(co.getContent().size());
  arr.set(co.getContent().buf());
  var content = this.ChatMessage.decode(arr.buffer);

  var temp = (new Date()).getTime();
  // if (temp - content.timestamp * 1000 < 120000)
  {
    var t = (new Date(content.timestamp * 1000)).toLocaleTimeString();
    var name = content.from;

    // chat_prefix should be saved as a name, not a URI string.
    var prefix = co.getName().getPrefix(-2).toUri();

    var session = parseInt((co.getName().get(-2)).toEscapedString());
    var seqno = parseInt((co.getName().get(-1)).toEscapedString());
    var l = 0;

    //update roster
    while (l < this.roster.length) {
      var name_t = this.roster[l].substring(0,this.roster[l].length-1);
      var session_t = this.roster[l].substring(this.roster[l].length-1,this.roster[l].length);
      if (name != name_t && content.type != 2)
        l++;
      else{
        if(name == name_t && session > session_t){
          this.roster[l] = name + session;
        }
        break;
      }
    }

    if(l == this.roster.length) {
      this.roster.push(name + session);

      document.getElementById('txt').innerHTML += '<div><b><grey>' + name + '-' +
        t + ': Join' + '</grey></b><br /></div>';
      var objDiv = document.getElementById("txt");
      objDiv.scrollTop = objDiv.scrollHeight;
      document.getElementById('menu').innerHTML = '<p><b>Member</b></p><ul>';
      for (var i = 0; i < this.roster.length ; i++) {
        var name_t = this.roster[i].substring(0,this.roster[i].length - 1);
        document.getElementById('menu').innerHTML += '<li>' + name_t + '</li>';
      }
      document.getElementById('menu').innerHTML += '</ul>';
    }
    /* TODO: Restore heartbeat functionality.
    var timeout = new Interest(new Name("/timeout"));
    timeout.setInterestLifetimeMilliseconds(120000);
    this.face.expressInterest(timeout, this.dummyOnData, this.alive.bind(this, timeout, seqno, name, session, prefix));
    */

    //if (content.type == 0 && this.isRecoverySyncState == false && content.from != this.screen_name){
      // Note: the original logic does not display old data;
      // But what if an ordinary application data interest gets answered after entering recovery state?
    if (content.type == 0) // && content.from != this.screen_name)
    {
      // Display on the screen will not display old data.
      // Encode special html characters to avoid script injection.
      var escaped_msg = $('<div/>').text(content.data).html();
      document.getElementById('txt').innerHTML +='<p><grey>' + content.from + '-' +
        t + ':</grey><br />' + escaped_msg + '</p>';
      var objDiv = document.getElementById("txt");
      objDiv.scrollTop = objDiv.scrollHeight;
    }
    else if (content.type == 2) {
      //leave message
      var n = this.roster.indexOf(name + session);
      if(n != -1 && name != this.screen_name) {
        this.roster.splice(n,1);
        document.getElementById('menu').innerHTML = '<p><b>Member</b></p><ul>';
        for(var i = 0; i<this.roster.length; i++) {
          var name_t = this.roster[i].substring(0,this.roster[i].length - 1);
          document.getElementById('menu').innerHTML += '<li>' + name_t + '</li>';
        }

        document.getElementById('menu').innerHTML += '</ul>';
        var d = new Date(content.timestamp * 1000);
        var t = d.toLocaleTimeString();
        document.getElementById('txt').innerHTML += '<div><b><grey>' + name +
          '-' + t + ': Leave</grey></b><br /></div>';
        var objDiv = document.getElementById("txt");
        objDiv.scrollTop = objDiv.scrollHeight;
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
  console.log("Timeout waiting for chat data");
};

/**
 *
 * @param {Interest}
 */
/* TODO: Restore heartbeat functionality.
ChronoChat.prototype.heartbeat = function(interest)
{
  // Based on ndn-cpp library approach
  if (this.msgcache.length == 0) {
    // Is it possible that this gets executed?
    this.messageCacheAppend("JOIN", "xxx");
  }
  this.sync.publishNextSequenceNo();
  this.messageCacheAppend("HELLO", "xxx");

  // Making a timeout interest for heartbeat...
  var timeout = new Interest(new Name("/timeout"));
  timeout.setInterestLifetimeMilliseconds(60000);

  //console.log("*** Chat heartbeat expressed interest with name: " + timeout.getName().toUri() + " ***");
  this.face.expressInterest(timeout, this.dummyOnData, this.heartbeat.bind(this));
};
*/

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
/* TODO: Restore heartbeat functionality.
ChronoChat.prototype.alive = function(interest, temp_seq, name, session, prefix)
{
  //console.log("check alive");
  var index_n = this.sync.digest_tree.find(prefix, session);
  var n = this.roster.indexOf(name + session);

  if (index_n != -1 && n != -1) {
    var seq = this.sync.digest_tree.digestnode[index_n].seqno_seq;
    if (temp_seq == seq) {
      this.roster.splice(n,1);
      console.log(name+" leave");
      var d = new Date();
      var t = d.toLocaleTimeString();

      document.getElementById('txt').innerHTML += '<div><b><grey>' + name + '-' +
        t + ': Leave</grey></b><br /></div>';
      var objDiv = document.getElementById("txt");
      objDiv.scrollTop = objDiv.scrollHeight;
      document.getElementById('menu').innerHTML = '<p><b>Member</b></p><ul>';
      for (var i = 0; i < this.roster.length; i++) {
        var name_t = this.roster[i].substring(0, this.roster[i].length - 10);
        document.getElementById('menu').innerHTML += '<li>' + name_t + '</li>';
      }
      document.getElementById('menu').innerHTML += '</ul>';
    }
  }
};
*/

ChronoChat.prototype.sendMessage = function()
{
  if (this.msgcache.length == 0)
    this.messageCacheAppend("JOIN", "xxx");

  var chatmsg = document.getElementById('fname').value.trim();
  if (chatmsg != "") {
    document.getElementById('fname').value = "";

    this.sync.publishNextSequenceNo();
    this.messageCacheAppend("CHAT", chatmsg);

    var d = new Date();
    var tt = d.toLocaleTimeString();
    // Encode special html characters to avoid script injection.
    var escaped_msg = $('<div/>').text(chatmsg).html();
    document.getElementById('txt').innerHTML += '<p><grey>' + this.screen_name +
      '-' + tt + ':</grey><br />' + escaped_msg + '</p>';
    var objDiv = document.getElementById("txt");
    objDiv.scrollTop = objDiv.scrollHeight;
  }
  else
    alert("Message cannot be empty");
}

/**
 * Send the leave message and leave.
 */
ChronoChat.prototype.leave = function()
{
  alert("Leaving the Chatroom...");
  $("#chat").hide();
  document.getElementById('room').innerHTML = 'Please close the window. Thank you';

  this.sync.publishNextSequenceNo();
  this.messageCacheAppend("LEAVE", "xxx");
};

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

  var usrseq = this.sync.getSequenceNo();

  this.msgcache.push(new ChronoChat.CachedMessage(usrseq, messageType, message, t));
  while (this.msgcache.length > this.maxmsgcachelength) {
    this.msgcache.shift();
  }
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

function getRandomNameString()
{
  var seed = 'qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM';
  var result = '';
  for (var i = 0; i < 3; i++) {
    var pos = Math.floor(Math.random() * seed.length);
    result += seed[pos];
  }
  return result;
};
