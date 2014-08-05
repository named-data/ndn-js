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

// For sha256 implementation; node.js syntax?
var crypto = require('crypto');

var DigestTree = function DigestTree()
{
  this.root = "00";
  this.digestnode = [];
};

exports.DigestTree = DigestTree;

// What is the meaning of a session?
// The equivalent for embedded class definition; reference: name.js
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

// prototype functions serve as member functions, called by instances of a class 
// (also an object, Javascript being a prototypical language)
DigestTree.Node.prototype.recomputeDigest = function()
{
  // TODO: SHA-256 implementation and check out the original logic
  
};

DigestTree.Node.int32ToLittleEndian = function(value, result)
{
  for (var i = 0; i < 4; i++) {
    result[i] = value % 256;
    value = value / 256;
  }
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
DigestTree.prototype.update = function(dataPrefix, sessionNo, sequenceNo)
{
  var n_index = this.find(dataPrefix, sessionNo);
  console.log("*** digest tree update ***");
  if (n_index >= 0) {
    if (this.digestnode[i].getSequenceNo() < sequenceNo)
      this.digestnode[i].setSequenceNo(sequenceNo);
    else
      return false;
  }
  else {
    /* Debug log outputs */
    // Is this the right way to create an object? new DigestTreeNode or DigestTree.Node?
    var temp = new DigestTree.Node(dataPrefix, sessionNo, sequenceNo);
    console.log("The node item to be pushed : " + temp);
    this.digestnode.push(temp);
  }
  this.recomputeRoot();
  return true;
  
  /*
      for(var i = 0;i<content.length;i++){
    if(content[i].type ==0){
        var n_index = this.find(content[i].name,content[i].seqno.session);
        console.log(content[i].name,content[i].seqno.session);
        console.log("n_index:"+n_index);
            if( n_index != -1){
        //only update the newer status
            if(this.digestnode[n_index].seqno.seq<content[i].seqno.seq){
                    if(self.chat_prefix == content[i].name){
                self.usrseq = content[i].seqno.seq;
                    }
            this.digestnode[n_index].seqno ={seq:content[i].seqno.seq,session:content[i].seqno.session};
            this.digestnode[n_index].prefix_name = content[i].name;
            var md = new KJUR.crypto.MessageDigest({alg: "sha256", prov: "cryptojs"});
                    md.updateHex(Int32ToHex(content[i].seqno.session)+Int32ToHex(content[i].seqno.seq));
                var digest_seq = md.digest();
                md = new KJUR.crypto.MessageDigest({alg: "sha256", prov: "cryptojs"});
                md.updateString(content[i].name);
                var digest_name = md.digest();
                md = new KJUR.crypto.MessageDigest({alg: "sha256", prov: "cryptojs"});
                md.updateHex(digest_name+digest_seq);

            this.digestnode[n_index].digest =md.digest();
                }
        }
            else{
                this.newcomer(content[i].name,content[i].seqno,self);
        }
        }
    }
    var md = new KJUR.crypto.MessageDigest({alg: "sha256", prov: "cryptojs"});
    for(var i = 0;i<this.digestnode.length;i++){
    md.updateHex(this.digestnode[i].digest);
    }
    this.root = md.digest();
    console.log("update root to: "+this.root);
    usrdigest = this.root;
  */
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
  var sha256;
  for (var i = 0; i < this.digestnode.length; ++i)
    SHA256_UpdateHex(sha256, this.digestnode[i].getDigest());
  var digest_root;
  // TODO: The equivalent of SHA256_Final
  
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

// This function should be tested, as the functions of hash related functions are unverified
function SHA256_UpdateHex(context, hex)
{
  var data = [];
  for (var i = 0; i < data.length; ++i)
    data[i] = 16 * fromHexChar(hex[2 * i]) + fromHexChar(hex[2 * i + 1]);
  // Update hash for given ascii hex
  var hash = crypto.createHash('sha256');
  // Default encoding for hash.update is 'binary'
  hash.update(data);
  context = hash.digest('hex');
};

function strcmp(component1, component2)
{
  return ( ( str1 == str2 ) ? 0 : ( ( str1 > str2 ) ? 1 : -1 ) );
};