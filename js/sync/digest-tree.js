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

/**
 * For now, the sequence of parameters in DigestTree.update is different from ndn-cpp;
 * Should use the same sequence of either (seq, ses) or (ses, seq) for all functions 
 * concerning them.
 */

/**
 * For now, KJUR and the referenced protobufjs are both locally installed Node.js packages
 */
var KJUR = require("jsrsasign");
var DataUtils = require("../encoding/data-utils.js").DataUtils;

var DigestTree = function DigestTree()
{
  this.root = "00";
  this.digestnode = [];
};

exports.DigestTree = DigestTree;

// What is the meaning of a session?
// DigestTree.Node works with seqno_seq and seqno_session, without protobuf definition,
// TODO: the corresponding chrono-sync2013 code is still dependent upon protobuf file.
// How is a DigestTree.Node different from ChronoSync2013.SyncState?
DigestTree.Node = function DigestTreeNode(dataPrefix, seqno_seq, seqno_session)
{
  // In this context, this should mean DigestTree.Node instead
  this.dataPrefix = dataPrefix;
  this.seqno_seq = seqno_seq;
  this.seqno_session = seqno_session;
  
  this.recomputeDigest();
};

DigestTree.Node.prototype.getDataPrefix = function()
{
  return this.dataPrefix;
};

DigestTree.Node.prototype.getSequenceNo = function()
{
  return this.seqno_seq;
};

DigestTree.Node.prototype.getSessionNo = function()
{
  return this.seqno_session;
};

DigestTree.Node.prototype.getDigest = function()
{
  return this.digest;
};

DigestTree.Node.prototype.setSequenceNo = function(sequenceNo)
{
  this.seqno_seq = sequenceNo;
  this.recomputeDigest();
};

// This works as digest-tree.cpp's int32ToLittleEndian
DigestTree.Node.prototype.Int32ToHex = function(value) {
  var result = new Uint8Array(8);
  for (var i = 0; i < 8; i++) {
    result[i] = value % 16;
    value = Math.floor(value / 16);
  }
  return result;
}

// After some experiments, this seems to yield the correct result for hashing
function bin2String(array) {
  return String.fromCharCode.apply(String, array);
}

function hexBufferToASCString(buffer)
{
  var result = [];
  for (var i = 0; i < buffer.length; i++) {
    if (buffer[i]>=0 && buffer[i]<=9) {
      result[i] = parseInt(buffer[i]) + 0x30;
    }
    else if (buffer[i]>=10 && buffer[i]<=16) {
      result[i] = parseInt(buffer[i]) + 0x41 - 10;
    }
    else {
      console.log("hex contains illegal number: " + buffer[i]);
    }
  }
  return bin2String(result);
}

DigestTree.Node.prototype.recomputeDigest = function()
{
  var md = new KJUR.crypto.MessageDigest({alg: "sha256", prov: "cryptojs"});
  
  md.updateHex(hexBufferToASCString(this.Int32ToHex(this.seqno_session)));
  md.updateHex(hexBufferToASCString(this.Int32ToHex(this.seqno_seq)));
  var digest_seq = md.digest();
  
  md = new KJUR.crypto.MessageDigest({alg: "sha256", prov: "cryptojs"});
  md.updateString(this.dataPrefix);
  var digest_name = md.digest();
  
  md = new KJUR.crypto.MessageDigest({alg: "sha256", prov: "cryptojs"});
  md.updateHex(digest_name + digest_seq);

  this.digest = md.digest();
};

// Do the work of string and then sequence number compare
DigestTree.Node.Compare = function(node1, node2)
{
  var nameComparison = strcmp(node1.dataPrefix, node2.dataPrefix);
  if (nameComparison != 0)
    return (nameComparison < 0);
  return (node1.seqno_session < node2.seqno_session);
};

/** 
 * Update the digest tree and recompute the root digest. If the combination of dataPrefix
 * and sessionNo already exists in the tree then update its sequenceNo (only if the given
 * sequenceNo is newer), otherwise add a new node.
 * @param {string} The name prefix.
 * @param {int} The session number.
 * @param {int} The sequence number.
 * @return True if the digest tree is updated, false if not
 */
DigestTree.prototype.update = function(dataPrefix, sequenceNo, sessionNo)
{
  var n_index = this.find(dataPrefix, sessionNo);
  if (n_index >= 0) {
    if (this.digestnode[n_index].getSequenceNo() < sequenceNo)
      this.digestnode[n_index].setSequenceNo(sequenceNo);
    else
      return false;
  }
  else {
    var temp = new DigestTree.Node(dataPrefix, sequenceNo, sessionNo);
    this.digestnode.push(temp);
    // Insert it to the place where it should go would be faster, though in our case
    // the difference in time should be minimal
    this.sortNodes();
  }
  this.recomputeRoot();
  return true;
};

/**
 * This function bubble-sorts the nodes in digestnode in lexi order.
 * Called every time when there's an update of nodes (or removal of nodes, which does
 * not seem to exist in current design/implementation).
 * This function does not exist in the original ChronoChat-JS implementation, 
 * and it's not strictly tested yet.
 */
DigestTree.prototype.sortNodes = function()
{
  var temp;
  for (var i = this.digestnode.length; i > 0; i--) {
    for (var j = 0; j < i - 1; j++) {
      if (this.digestnode[j].getDataPrefix() > this.digestnode[j + 1].getDataPrefix()) {
        temp = this.digestnode[j];
        this.digestnode[j] = this.digestnode[j + 1];
        this.digestnode[j + 1] = temp;
      }
    }
  }
};

DigestTree.prototype.find = function(dataPrefix, sessionNo)
{
  for (var i = 0; i < this.digestnode.length; ++i) {
    if (this.digestnode[i].getDataPrefix() == dataPrefix && 
        this.digestnode[i].getSessionNo() == sessionNo)
      return i;
  }
  return -1;
};

DigestTree.prototype.size = function()
{
  return this.digestnode.size();
};

// Not really used
DigestTree.prototype.get = function(i)
{
  return this.digestnode[i];
};

DigestTree.prototype.getRoot = function()
{
  return this.root;
};

DigestTree.prototype.recomputeRoot = function()
{
  var md = new KJUR.crypto.MessageDigest({alg: "sha256", prov: "cryptojs"});
  // The result of updateHex is related with the sequence of participants,
  // I don't think that should be the case.
  for (var i = 0; i < this.digestnode.length; i++) {
    md.updateHex(this.digestnode[i].digest);
  }
  this.root = md.digest();
  //console.log("update root to: " + this.root);
};

// Not sure if this ascii representation works yet
function fromHexChar(c)
{
  if (c >= '0' && c <= '9')
    return (c - '0');
  else if (c >= 'a' && c <= 'f')
    return (c - 'a' + 10);
  else if (c >= 'A' && c<= 'F')
    return (c - 'A' + 10);
  else
    return -1;
};

function strcmp(component1, component2)
{
  return ( ( str1 == str2 ) ? 0 : ( ( str1 > str2 ) ? 1 : -1 ) );
};