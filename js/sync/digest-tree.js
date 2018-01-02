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

// Use capitalized Crypto to not clash with the browser's crypto.subtle.
/** @ignore */
var Crypto = require('../crypto.js');

/**
 * @constructor
 */
var DigestTree = function DigestTree()
{
  this.root = "00";
  this.digestnode = [];
};

exports.DigestTree = DigestTree;

// The meaning of a session is explained here:
// http://named-data.net/doc/ndn-ccl-api/chrono-sync2013.html
// DigestTree.Node works with seqno_seq and seqno_session, without protobuf definition,
DigestTree.Node = function DigestTreeNode(dataPrefix, seqno_session, seqno_seq)
{
  // In this context, this should mean DigestTree.Node instead
  this.dataPrefix = dataPrefix;
  this.seqno_session = seqno_session;
  this.seqno_seq = seqno_seq;

  this.recomputeDigest();
};

DigestTree.Node.prototype.getDataPrefix = function()
{
  return this.dataPrefix;
};

DigestTree.Node.prototype.getSessionNo = function()
{
  return this.seqno_session;
};

DigestTree.Node.prototype.getSequenceNo = function()
{
  return this.seqno_seq;
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

// Using Node.JS buffer, as documented here http://nodejs.org/api/buffer.html.
DigestTree.Node.prototype.Int32ToBuffer = function(value) {
  var result = new Buffer(4);
  for (var i = 0; i < 4; i++) {
    result[i] = value % 256;
    value = Math.floor(value / 256);
  }
  return result;
}

DigestTree.Node.prototype.recomputeDigest = function()
{
  var seqHash = Crypto.createHash('sha256');

  seqHash.update(this.Int32ToBuffer(this.seqno_session));
  seqHash.update(this.Int32ToBuffer(this.seqno_seq));

  var digest_seq = seqHash.digest();

  var nameHash = Crypto.createHash('sha256');
  nameHash.update(this.dataPrefix);
  var digest_name = nameHash.digest();

  var hash = Crypto.createHash('sha256');
  hash.update(digest_name);
  hash.update(digest_seq);

  this.digest = hash.digest('hex');
};

// Do the work of string and then sequence number compare
DigestTree.Node.Compare = function(node1, node2)
{
  if (node1.dataPrefix != node2.dataPrefix)
    return node1.dataPrefix < node2.dataPrefix;
  return node1.seqno_session < node2.seqno_session;
};

/**
 * Update the digest tree and recompute the root digest. If the combination of dataPrefix
 * and sessionNo already exists in the tree then update its sequenceNo (only if the given
 * sequenceNo is newer), otherwise add a new node.
 * @param {string} The name prefix.
 * @param {int} sessionNo The session number.
 * @param {int} sequenceNo The sequence number.
 * @return True if the digest tree is updated, false if not
 */
DigestTree.prototype.update = function(dataPrefix, sessionNo, sequenceNo)
{
  var n_index = this.find(dataPrefix, sessionNo);
  if (n_index >= 0) {
    if (this.digestnode[n_index].getSequenceNo() < sequenceNo)
      this.digestnode[n_index].setSequenceNo(sequenceNo);
    else
      return false;
  }
  else {
    var temp = new DigestTree.Node(dataPrefix, sessionNo, sequenceNo);
    this.digestnode.push(temp);
    this.digestnode.sort(this.sortNodes);
  }
  this.recomputeRoot();
  return true;
};

// Need to confirm this sort works with the insertion in ndn-cpp.
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

DigestTree.prototype.sortNodes = function (node1, node2)
{
  if (node1.getDataPrefix() == node2.getDataPrefix() &&
     node1.getSessionNo() == node2.getSessionNo())
    return 0;

  if ((node1.getDataPrefix() > node2.getDataPrefix()) ||
     ((node1.getDataPrefix() == node2.getDataPrefix()) &&
     (node1.getSessionNo() >node2.getSessionNo())))
    return 1;
  else
    return -1;
}

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
  var md = Crypto.createHash('sha256');
  // The result of updateHex is related with the sequence of participants,
  // I don't think that should be the case.
  for (var i = 0; i < this.digestnode.length; i++) {
    md.update(new Buffer(this.digestnode[i].digest, 'hex'));
  }
  this.root = md.digest('hex');
};
