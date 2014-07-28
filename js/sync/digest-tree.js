/**
 * This class represents the digest tree for chrono-sync2013.
 * Copyright (C) 2013-2014 Regents of the University of California.
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
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var DigestTree = function DigestTree()
{
  this.root = "00";
}

// What is the meaning of a session?
// The equivalent for embedded class definition; reference: name.js
var DigestTree.Node = function DigestTreeNode(dataPrefix, seqno_seq, seqno_session)
{
  // In this context, this should mean DigestTree.Node instead
  this.dataPrefix = dataPrefix;
  this.seqno_seq = seqno_seq;
  this.seqno_session = seqno_session;
  
  this.recomputeDigest();
}

DigestTree.Node.prototype.getDataPrefix = function()
{
  return this.dataPrefix;
}

DigestTree.Node.prototype.getSequenceNo = function()
{
  return this.seqno_seq;
}

DigestTree.Node.prototype.getSessionNo = function()
{
  return this.seqno_session;
}

DigestTree.Node.prototype.getDigest = function()
{
  return this.digest;
}

DigestTree.Node.prototype.setSequenceNo = function(sequenceNo)
{
  this.seqno_seq = sequenceNo;
  this.recomputeDigest();
}

// prototype functions serve as member functions, called by instances of a class 
// (also an object, Javascript being a prototypical language)
DigestTree.Node.prototype.recomputeDigest = function()
{
  
}

DigestTree.Node.int32ToLittleEndian = function(value, result)
{

}

function strcmp(component1, component2)
{
  return ( ( str1 == str2 ) ? 0 : ( ( str1 > str2 ) ? 1 : -1 ) );
}

// Do the work of string and then sequence number compare
DigestTree.Node.Compare = function(node1, node2)
{
  var nameComparison = strcmp(node1.dataPrefix, node2.dataPrefix);
  if (nameComparison != 0)
    return (nameComparison < 0);
  return (node1.seqno_session < node2.seqno_session);
}

DigestTree.prototype.update = function(dataPrefix, sessionNo, sequenceNo)
{
  var n_index = this.find(dataPrefix, sessionNo);
  /* Debug log outputs */
  if (n_index >= 0) {
    if (this.digestnode[i].getSequenceNo() < sequenceNo)
      this.digestnode[i].setSequenceNo(sequenceNo);
    else
      return false;
  }
  else {
    /* Debug log outputs */
    // Is this the right way to create an object? new DigestTreeNode or DigestTree.Node?
    var temp = new DigestTreeNode(dataPrefix, sessionNo, sequenceNo);
    // this.digestnode is a vector, looking for its equivalent in js.
    //this.digestnode.insert(temp);
  }
}

DigestTree.prototype.find = function(dataPrefix, sessionNo)
{
  for (var i = 0; i < this.digestnode.size(); ++i) {
    if (this.digestnode[i].getDataPrefix() == dataPrefix && 
        this.digestnode[i].getSessionNo() == sessionNo)
      return i;
  }
  return -1;
}

DigestTree.prototype.size = function()
{
  return this.digestnode.size();
}

DigestTree.prototype.get = function(i)
{
  return this.digestnode[i];
}

DigestTree.prototype.getRoot = function()
{
  return this.root;
}

DigestTree.prototype.recomputeRoot = function()
{
  
}