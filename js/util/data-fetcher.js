/**
 * Copyright (C) 2015-2018 Regents of the University of California.
 * @author: Chavoosh Ghasemi <chghasemi@cs.arizona.edu>
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
var Interest = require('../interest.js').Interest; /** @ignore */
var LOG = require('../log.js').Log.LOG;

/**
 * DataFetcher is a utility class to fetch Data with automatic retries.
 *
 * This is a public constructor to create a new DataFetcher object.
 * @param {Face} face The segment will be fetched through this face.
 * @param {Interest} interest Use this as the basis of the future issued Interest(s) to fetch
 * the solicited segment.
 * @param {int} maxTimeoutRetries The max number of retries upon facing Timeout.
 * @param {int} maxNackRetries The max number of retries upon facing Nack.
 * @param {function} onData Call this function upon receiving the Data packet for the
 * solicited segment.
 * @param {function} onTimeout Call this function after receiving Timeout for more than
 * maxTimeoutRetries times. 
 * @param {function} onNack Call this function after receiving Nack for more than
 * maxNackRetries times.
 * @constructor
 *
 */
var DataFetcher = function DataFetcher
  (face, interest, maxTimeoutRetries, maxNackRetries, onData, onTimeout, onNack)
{
  this.face = face;
  this.interest = interest;
  this.maxNackRetries = maxNackRetries;
  this.maxTimeoutRetries = maxTimeoutRetries;

  this.onData = onData;
  this.onTimeout = onTimeout;
  this.onNack = onNack;

  this.numberOfTimeoutRetries = 0;
  this.pendingInterestId = null;
};

exports.DataFetcher = DataFetcher;

DataFetcher.prototype.fetch = function()
{
  this.pendingInterestId = this.face.expressInterest
    (this.interest,
     this.handleData.bind(this),
     this.handleTimeout.bind(this),
     this.handleNack.bind(this));
};

DataFetcher.prototype.cancelPendingInterest = function()
{
  this.face.removePendingInterest(this.pendingInterestId);
};

DataFetcher.prototype.handleData = function(originalInterest, data)
{
  this.onData(originalInterest, data);
};

DataFetcher.prototype.handleTimeout = function(interest)
{
  this.numberOfTimeoutRetries++;
  if (this.numberOfTimeoutRetries <= this.maxTimeoutRetries) {
    var newInterest = new Interest(interest);
    newInterest.refreshNonce();
    this.interest = newInterest;
    if (LOG > 3)
      console.log('handle timeout for interest ' + interest.getName());
    this.fetch();
  }
  else {
    this.onTimeout(interest);
  }
};

DataFetcher.prototype.handleNack = function(interest)
{
  this.numberOfNackRetries += 1;
  if (this.numberOfNackRetries <= this.maxNackRetries) {
    var newInterest = new Interest(interest);
    newInterest.refreshNonce();
    this.interest = newInterest;
    if (LOG > 3)
      console.log('handle nack for interest ' + interest.getName());
    // wait 40 - 60 ms before issuing a new Interest after receiving a Nack
    setTimeout(this.fetch.bind(this), 40 + Math.random() * 20);
  }
  else {
    this.onNack(interest);
  }
};
