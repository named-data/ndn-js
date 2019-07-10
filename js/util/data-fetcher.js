/**
 * Copyright (C) 2018-2019 Regents of the University of California.
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
var Pipeline = require('./pipeline.js').Pipeline;

/**
 * DataFetcher is a utility class to fetch Data with automatic retries.
 *
 * This is a public constructor to create a new DataFetcher object.
 * @param {Face} face The segment will be fetched through this face.
 * @param {Interest} interest Use this as the basis of the future issued Interest(s) to fetch
 *                            the solicited segment.
 * @param {int} maxRetriesOnTimeoutOrNack The max number of retries upon facing Timeout or Nack.
 * @param {function} onData Call this function upon receiving the Data packet for the
 *                          solicited segment.
 * @param {function} onFailure Call this function after receiving Timeout or Nack for more than
 *                             maxRetriesOnTimeoutOrNack times.
 * @param {Object} segmentInfo An object that tracks the important information about each segment.
 *                             E.g., number of retries upon timeout and nack.
 * @param {Object} stats An object that containes statistics of content retrieval performance.
 *
 * @constructor
 */
var DataFetcher = function DataFetcher
  (face, interest, maxRetriesOnTimeoutOrNack, onData, handleFailure, segmentInfo, stats)
{
  this.face = face;
  this.interest = interest;
  this.maxRetriesOnTimeoutOrNack = maxRetriesOnTimeoutOrNack;

  this.onData = onData;
  this.handleFailure = handleFailure;

  this.segmentInfo = segmentInfo;
  this.stats = stats;

  this.segmentNo = 0; // segment number of the current Interest
  if (interest.getName().components.length > 0 && interest.getName().get(-1).isSegment()) {
    this.segmentNo = interest.getName().get(-1).toSegment();
  }

  this.nTimeoutRetries = 0;
  this.nNackRetries = 0;

  this.segmentInfo[this.segmentNo] = {};
  this.segmentInfo[this.segmentNo].stat = "normal";
  this.segmentInfo[this.segmentNo].initTimeSent = Date.now();

  this.pendingInterestId = null;
};

exports.DataFetcher = DataFetcher;

DataFetcher.prototype.fetch = function()
{
  this.segmentInfo[this.segmentNo].timeSent = Date.now();
  this.pendingInterestId = this.face.expressInterest
    (this.interest,
     this.handleData.bind(this),
     this.handleLifetimeExpiration.bind(this),
     this.handleNack.bind(this));
};

DataFetcher.prototype.getPendingInterestId = function()
{
  return this.pendingInterestId;
};

DataFetcher.prototype.handleData = function(interest, data)
{
  this.stats.nTimeouts += this.nTimeoutRetries;
  this.stats.nNacks += this.nNackRetries;
  this.stats.nRetransmitted += (this.nNackRetries + this.nTimeoutRetries);
  this.onData(interest, data);
};

DataFetcher.prototype.handleLifetimeExpiration = function(interest)
{
  this.nTimeoutRetries++;
  this.segmentInfo[this.segmentNo].stat = "retx";
  if (this.nTimeoutRetries <= this.maxRetriesOnTimeoutOrNack) {
    var newInterest = new Interest(interest);
    newInterest.refreshNonce();
    this.interest = newInterest;
    if (LOG > 3)
      console.log('handle timeout for interest ' + interest.getName());
    this.fetch();
  }
  else {
    var segNo = 0;
    if (interest.getName().components.length > 0 && interest.getName().get(-1).isSegment()) {
      segNo = interest.getName().get(-1).toSegment();
    }

    this.handleFailure(this.segmentNo, Pipeline.ErrorCode.MAX_NACK_TIMEOUT_RETRIES,
         "Reached the maximum number of retries (" +
          this.maxRetriesOnTimeoutOrNack + ") while retrieving segment #" + segNo);
  }
};

DataFetcher.prototype.handleNack = function(interest)
{
  this.nNackRetries += 1;
  this.segmentInfo[this.segmentNo].stat = "retx";
  if (this.nNackRetries <= this.maxRetriesOnTimeoutOrNack) {
    var newInterest = new Interest(interest);
    newInterest.refreshNonce();
    this.interest = newInterest;
    if (LOG > 3)
      console.log('handle nack for interest ' + interest.getName());
    // wait 40 - 60 ms before issuing a new Interest after receiving a Nack
    setTimeout(this.fetch.bind(this), 40 + Math.random() * 20);
  }
  else {
    var segNo = 0;
    if (interest.getName().components.length > 0 && interest.getName().get(-1).isSegment()) {
      segNo = interest.getName().get(-1).toSegment();
    }

    this.handleFailure(this.segmentNo, Pipeline.ErrorCode.MAX_NACK_TIMEOUT_RETRIES,
         "Reached the maximum number of retries (" +
          this.maxRetriesOnTimeoutOrNack + ") while retrieving segment #" + segNo);
  }
};
