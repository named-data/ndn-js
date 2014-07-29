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

// TODO: the equivalent of function pointers, or are there no such things?
// The point of naming it as 'argn'? just to correspond with boost::bind?
// Assuming that it takes the form of (OnReceivedSyncState, OnInitialized, 
// applicationDataPrefix, applicationBroadcastPrefix, sessionNo, face, 
// keyChain, certificateName, syncLifetime, onRegisterFailed)
var ChronoSync2013 = function ChronoSync2013(arg1, arg2, applicationDataPrefix, applicationBroadcastPrefix, sessionNo, face, keyChain, certificateName, arg9)
{
  
}

// SyncState class

var ChronoSync2013.SyncState = function ChronoSync2013SyncState(dataPrefixUri, sessionNo, sequenceNo)
{
  this.dataPrefixUri = dataPrefixUri;
  this.sessionNo = sessionNo;
  this.sequenceNo = sequenceNo;
}

ChronoSync2013.SyncState.prototype.getDataPrefix = function()
{
  return this.dataPrefixUri;
}

ChronoSync2013.SyncState.prototype.getSessionNo = function()
{
  return this.sessionNo;
}

ChronoSync2013.SyncState.prototype.getSequenceNo = function()
{
  return this.sequenceNo;
}

ChronoSync2013.prototype.getProducerSequenceNo = function(dataPrefix, sessionNo)
{
  
}

ChronoSync2013.prototype.publishNextSequenceNo = function()
{

}

ChronoSync2013.prototype.getSequenceNo = function()
{
  return this.usrseq;
}

// DigestLogEntry class

ChronoSync2013.DigestLogEntry = function ChronoSync2013DisgestLogEntry(digest, data)
{

}

ChronoSync2013.DigestLogEntry.prototype.getDigest = function()
{
  return this.digest;
}

ChronoSync2013.DigestLogEntry.prototype.getData = function()
{
  return this.data;
}

// PendingInterest class

var ChronoSync2013.PendingInterest = function ChronoSync2013PendingInterest(interest, transport)
{

}

ChronoSync2013.PendingInterest.prototype.getInterest = function()
{
  return this.interest;
}

ChronoSync2013.PendingInterest.prototype.getTransport = function()
{
  return this.transport;
}

ChronoSync2013.PendingInterest.prototype.isTimedOut = function(nowMilliseconds)
{
  return (this.timeoutTimeMilliseconds >= 0.0 && nowMilliseconds >= this.timeoutTimeMilliseconds);
}

// Private methods for ChronoSync2013 class, TODO: fill implementation and comments into the skeleton.

ChronoSync2013.prototype.broadcastSyncState = function(digest, syncMessage)
{

}

ChronoSync2013.prototype.update = function(content)
{

}

ChronoSync2013.prototype.logfind = function(digest)
{

}

ChronoSync2013.prototype.onInterest = function(prefix, inst, transport, registerPrefixId)
{

}

ChronoSync2013.prototype.onData = function(inst, co)
{

}

ChronoSync2013.prototype.initialTimeout = function(interest)
{

}

ChronoSync2013.prototype.processRecoveryInst = function(inst, syncdigest, transport)
{

}

ChronoSync2013.prototype.processSyncInst = function(index, syncdigest_t, transport)
{

}

ChronoSync2013.prototype.sendRecovery = function(syncdigest_t)
{

}

ChronoSync2013.prototype.judgeRecovery = function(interest, syncdigest_t, transport)
{

}

ChronoSync2013.prototype.syncTimeout = function(interest)
{

}

ChronoSync2013.prototype.initialOndata = function(content)
{

}

ChronoSync2013.prototype.contentCacheAdd = function(data)
{

}

ChronoSync2013.prototype.dummyOnData = function(interest, data)
{

}