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
var NdnCommon = require('./ndn-common.js').NdnCommon;

/**
 * Here are some basic assumptions and logics that are applied to all pipelines in the library:
 *
 * Name of data packets look like /<prefix>/<version>/<segment>, where:
 * - <prefix>  is the specified name prefix,
 * - <version> is an unknown version that needs to be discovered, and
 * - <segment> is a segment number.
 *
 * Note: The number of segments is unknown and is controlled by
 *       `FinalBlockId` field in one of the retrieved Data packet.
 *       This field MUST exist at least in the last Data packet.
 *
 * The following logic is implemented in all pipelines:
 *
 * 1. If the version is not provided in Interest's name, then express the first Interest
 *    to discover the version:
 *
 *    >> Interest: /<prefix>?MustBeFresh=true
 *
 *    Otherwise, express the following Interest:
 *
 *    >> Interest: /<prefix>/version/%00%00?MustBeFresh=false
 *
 * 2. Infer the latest version of the Data: <version> = Data.getName().get(-2)
 *
 * If an error occurs during the fetching process, the onError callback is called
 * with a proper error code. The following errors might be raised by any pipeline:
 *
 * - `INTEREST_TIMEOUT`: if any of the Interests times out.
 * - `INTEREST_LIFETIME_EXPIRATION`: if lifetime of any Interest expires in the PIT table.
 * - `DATA_HAS_NO_VERSION`: if the the second last name component of the first received Data
 *                          packet is not version number.
 * - `DATA_HAS_NO_SEGMENT`: if any of the retrieved Data packets does not have a segment
 *                          as the last component of the name (not counting the implicit digest).
 * - `SEGMENT_VERIFICATION_FAILED`: if any retrieved segment fails
 *                                  the KeyChain verifyData.
 * - `NACK_RECEIVED`: if a Nack is received.
 * - `NO_FINALBLOCK`: if none of the received Data packets (including the last one) do not have
 *                    finalBlockId.
 * - `MAX_NACK_TIMEOUT_RETRIES`: after a proper number of retries to fetch a given segment, if
 *                               the corresponding segment is an essential part of the content
 *                               (i.e., segmentNo <= finalBlockId), this error will be raised.
 * - `MISC`: miscellaneous errors (preferably an error reason should be provided).
 *
 * In order to validate individual segments, a KeyChain needs to be supplied to a given pipeline.
 * If verifyData fails, the fetching process is aborted with SEGMENT_VERIFICATION_FAILED.
 * If data validation is not required just pass null.
 */
var Pipeline = function Pipeline (baseInterest) {
  this.baseInterest = baseInterest;
  this.nextSegmentNo = 0;
  this.numberOfSatisfiedSegments = 0;
  this.finalBlockId = Number.MAX_SAFE_INTEGER;
  this.versionNo = NaN; // set by name of the baseInterest or the first received Data packet
  this.versionIsProvided = false;  // whether baseInterest's name contains version number
  if (baseInterest.getName().components.length > 0 && baseInterest.getName().get(-1).isVersion()) {
    this.versionNo = baseInterest.getName().get(-1).toVersion();
    this.versionIsProvided = true;
  }

  this.isStopped = false; // false means the pipeline is running
  this.hasFailure = false;
  this.hasFinalBlockId = false;
  this.failedSegNo = 0;
  this.failureReason;
  this.failureErrorCode;

  this.contentParts = []; // buffer (no duplicate entry)
}

exports.Pipeline = Pipeline;

/**
 * An ErrorCode value is passed in the onError callback.
 */
Pipeline.ErrorCode = {
  INTEREST_TIMEOUT: 1,
  INTEREST_LIFETIME_EXPIRATION: 2,
  DATA_HAS_NO_VERSION: 3,
  DATA_HAS_NO_SEGMENT: 4,
  SEGMENT_VERIFICATION_FAILED: 5,
  NACK_RECEIVED: 6,
  NO_FINALBLOCK: 7,
  MAX_NACK_TIMEOUT_RETRIES: 8,
  MISC: 9
};

/**
 * Stop the pipeline
 */
Pipeline.prototype.cancel = function()
{
  if (this.isStopped)
    return;

  this.isStopped = true;
};

/**
 * Make an Interest with proper name
 * @description If baseInterest's name contains version number it will be used, otherwise the
 *              discovered version number will be used. Then @param segNo is appended to the name.
 *              If no version number is available, we send back a copy of baseInterest.
 */
Pipeline.prototype.makeInterest = function(segNo)
{
  var interest = new Interest(this.baseInterest);

  if (!Number.isNaN(this.versionNo) ) {
    if (this.versionIsProvided === false) {
      interest.setName(new Name(this.baseInterest.getName())
                       .appendVersion(this.versionNo)
                       .appendSegment(segNo));
    }
    else {
      interest.setName(new Name(this.baseInterest.getName())
                       .appendSegment(segNo));
    }
  }
  return interest;
};

Pipeline.prototype.getNextSegmentNo = function()
{
  return this.nextSegmentNo++;
};

Pipeline.op = function (arg, def, opts)
{
  if (opts == null)
    return def;
  if (!opts.hasOwnProperty(arg))
    return def;
  return opts[arg];
};

Pipeline.reportWarning = function(errCode, msg)
{
  console.log("Warning " + errCode + " : " + msg);
};

Pipeline.reportError = function(onError, errCode, msg)
{
  try {
    onError(errCode, msg);
  } catch (ex) {
    console.log("Error in onError: " + NdnCommon.getErrorWithStackTrace(ex));
  }
};

/**
 * @param {Pipeline.ErrorCode} errCode One of the predefined error codes.
 * @param {string} reason A short description about the error.
 * @param {function} onError Call onError(errorCode, message) for any error during content retrieval
 *                           (see Pipeline documentation for ful list of errors).
 * @param {function} cancel If no function is provided then the local cancel function will run.
 */
Pipeline.prototype.onFailure = function(errCode, reason, onError, cancel)
{
  if (cancel == null)
    this.cancel();
  else
    cancel();

  Pipeline.reportError(onError, errCode, reason);
};
