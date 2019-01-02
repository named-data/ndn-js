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
var NdnCommon = require('./ndn-common.js').NdnCommon;
var LOG = require('../log.js').Log.LOG;

/**
 * DataFetcher is a utility class to resolve a given segment.
 *
 * This is a public constructor to create a new DataFetcher object.
 * @param {Pipeline} pipe This is a pipeline that is in charge of retrieving
 * the segmented data. We need this pointer for callbacks.
 * NOTE: All pipelines MUST implement onData, onNack, and onTimeout methods.
 * @param {Face} face The segment will be fetched through this face.
 * @param {Interest} interest Use this as the basis of the future issued Interest(s) to fetch
 * the solicited segment.
 * @param {int} maxNackRetries The max number of retries upon facing Nack.
 * @param {int} maxTimeoutRetries The max number of retries upon facing Timeout.
 * @param {function} onData Call this function upon receiving the Data packet for the
 * solicited segment.
 * @param {function} onNack Call this function after receiving Nack for more than
 * maxNackRetries times.
 * @param {function} onNack Call this function after receiving Timeout for more than
 * maxTimeoutRetries times.
 * @constructor
 */
var DataFetcher = function DataFetcher
  (pipe, face, interest, maxNackRetries, maxTimeoutRetries, onData, onNack, onTimeout)
{
  this.pipe = pipe;
  this.face = face;
  this.interest = interest;
  this.maxNackRetries = maxNackRetries;
  this.maxTimeoutRetries = maxTimeoutRetries;

  this.numberOfTimeoutRetries = 0;
};

exports.DataFetcher = DataFetcher;

DataFetcher.prototype.fetch = function()
{
  this.face.expressInterest
    (this.interest,
     this.handleData.bind(this),
     this.handleTimeout.bind(this),
     this.handleNack.bind(this));
};

DataFetcher.prototype.handleData = function(originalInterest, data)
{
  this.pipe.onData(originalInterest, data);
};

DataFetcher.prototype.handleTimeout = function(interest)
{
  this.numberOfTimeoutRetries++;
  if(this.numberOfTimeoutRetries <= this.maxTimeoutRetries) {
    var newInterest = new Interest(interest);
    newInterest.setMustBeFresh(true);
    newInterest.refreshNonce();
    this.interest = newInterest;
    if (LOG > 3)
      console.log('handle timeout for interest ' + interest.getName());
    this.fetch();
  }
  else {
    this.pipe.onTimeout(interest);
  }
};

DataFetcher.prototype.handleNack = function(interest)
{
  this.numberOfNackRetries += 1;
  if(this.numberOfNackRetries <= this.maxNackRetries) {
    var newInterest = new Interest(interest);
    newInterest.setMustBeFresh(true);
    newInterest.refreshNonce();
    this.interest = newInterest;
    if (LOG > 3)
      console.log('handle nack for interest ' + interest.getName());
    this.fetch();
  }
  else {
    this.pipe.onNack(interest);
  }
};
