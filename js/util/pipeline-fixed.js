/**
 * Copyright (C) 2018-2019 Regents of the University of California.
 * @author: Chavoosh Ghasemi <chghasemi@cs.arizona.edu>
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

/** @ignore */
var Interest = require('../interest.js').Interest; /** @ignore */
var Blob = require('./blob.js').Blob; /** @ignore */
var KeyChain = require('../security/key-chain.js').KeyChain; /** @ignore */
var NdnCommon = require('./ndn-common.js').NdnCommon;
var DataFetcher = require('./data-fetcher.js').DataFetcher;
var Pipeline = require('./pipeline.js').Pipeline;

/**
 * Retrieve the segments of solicited data by keeping a fixed-size window of N
 * of on fly Interests at any given time.
 *
 * To handle timeout and nack we use DataFetcher class which upon facing
 * timeout or nack will try to resolve the corresponded segment by retransmitting
 * the Interest a few times.
 *
 * After discovering the version number from the very first Data packet
 * (see Pipeline documentation), then:
 *
 * 1. Pipeline the Interests starting from segment 0:
 *
 *    >> Interest: /<prefix>/<version>/<segment=0>
 *    >> Interest: /<prefix>/<version>/<segment=1>
 *    ...
 *    >> Interest: /<prefix>/<version>/<segment=this.windowSize-1>
 *
 * We do not issue interest for segments that are already received.
 * At any given time the number of on the fly Interests should be equal
 * to this.windowSize. The next expected segment to fetch will be this.windowSize
 *
 * 2. Upon receiving a valid Data back we pipeline an Interest for the
 *    next expected segment.
 *
 * We repeat step 2 until the FinalBlockId === Data.getName().get(-1).
 *
 * 3. Call the onComplete callback with a Blob that concatenates the content
 *    from all segments.
 *
 * If an error occurs during the fetching process, the onError callback is called
 * with a proper error code (see Pipeline documenation).
 *
 * This is a public constructor to create a new PipelineFixed.
 * @param {Interest} baseInterest This interest should be well-formed to represent all necessary fields
 *                                 that the application wants to use for all Interests (e.g., interest
 *                                 lifetime).
 * @param {Face} face The segments will be fetched through this face.
 * @param {Object} opts An object that can contain pipeline options to overwrite their default values.
 *                      If null is passed then all pipeline options will be set to their default values.
 * @param {KeyChain} validatorKeyChain If this is not null, use its verifyData otherwise skip
 *                                     Data validation.
 * @param {function} onComplete When all segments are received, call onComplete(content) where content
 *                              is a Blob which has the concatenation of the content of all the segments.
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onError Call onError(errorCode, message) for any error during content retrieval
 *                           (see Pipeline documentation for ful list of errors).
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @constructor
 */
var PipelineFixed = function PipelineFixed
  (baseInterest, face, opts, validatorKeyChain, onComplete, onError)
{
  this.baseInterest = baseInterest;
  this.face = face;
  this.validatorKeyChain = validatorKeyChain;
  this.onComplete = onComplete;
  this.onError = onError;

  this.numberOfSatisfiedSegments = 0;
  this.nextSegmentToRequest = 0;
  this.segmentsOnFly = 0;
  this.finalBlockId = Number.MAX_SAFE_INTEGER;

  // Options
  this.windowSize = Pipeline.op("windowSize", 10, opts);
  this.maxTimeoutRetries = Pipeline.op("maxTimeoutRetries", 3, opts);
  this.maxNackRetries = Pipeline.op("maxNackRetries", 3, opts);

  this.contentParts = []; // of Buffer (no duplicate entry)
  this.dataFetchersContainer = []; // if we need to cancel pending interests
};

exports.PipelineFixed = PipelineFixed;

/**
 * Use DataFetcher to fetch the solicited segment. Timeouts and Nacks will be
 * handled by DataFetcher class.
 */
PipelineFixed.prototype.fetchSegment = function(interest)
{
  if (interest.getName().get(-1).isSegment()) {
    var segmentNo = interest.getName().get(-1).toSegment();
    this.dataFetchersContainer[segmentNo] = new DataFetcher
      (this.face, interest, this.maxTimeoutRetries, this.maxNackRetries,
       this.onData.bind(this), this.onTimeout.bind(this), this.onNack.bind(this));
       this.dataFetchersContainer[segmentNo].fetch();
  }
  else { // do not keep track of very first interest
    (new DataFetcher
      (this.face, interest, this.maxTimeoutRetries, this.maxNackRetries,
       this.onData.bind(this), this.onTimeout.bind(this), this.onNack.bind(this)))
       .fetch();

  }
};

PipelineFixed.prototype.run = function()
{
  var interest = new Interest(this.baseInterest);
  interest.setMustBeFresh(true);

  this.fetchSegment(interest);
};

PipelineFixed.prototype.fetchNextSegments = function (originalInterest, dataName)
{
  var interest = new Interest(originalInterest);
  // Changing a field clears the nonce so that a new nonce will be generated
  interest.setMustBeFresh(false);

  while (this.nextSegmentToRequest <= this.finalBlockId && this.segmentsOnFly <= this.windowSize) {
    // do not re-send an interest for existing segments
    if (this.contentParts[this.nextSegmentToRequest] !== undefined) {
      this.nextSegmentToRequest += 1;
      continue;
    }

    interest.setName(dataName.getPrefix(-1).appendSegment(this.nextSegmentToRequest));
    interest.refreshNonce();

    this.fetchSegment(interest);

    this.nextSegmentToRequest += 1;
    this.increaseNumberOfSegmentsOnFly();
  }
};

PipelineFixed.prototype.cancelPendingInterestsAboveFinalBlockId = function ()
{
  var len = this.dataFetchersContainer.length;

  for (var i = this.finalBlockId + 1; i < len; i++) {
    if (this.dataFetchersContainer[i] !== null) {
      this.dataFetchersContainer[i].cancelPendingInterest();
    }
  }
};

PipelineFixed.prototype.onData = function(originalInterest, data)
{
  if (this.validatorKeyChain !== null) {
    try {
      var thisPipeline = this;
      this.validatorKeyChain.verifyData
        (data,
         function(localData) {
           thisPipeline.onVerified(localData, originalInterest);
         },
         this.onValidationFailed.bind(this));
    } catch (ex) {
      Pipeline.reportError(this.onError, Pipeline.ErrorCode.SEGMENT_VERIFICATION_FAILED,
                       "Error in KeyChain.verifyData: " + ex);
    }
  }
  else {
    this.onVerified(data, originalInterest);
  }
};

PipelineFixed.prototype.onVerified = function(data, originalInterest)
{
  var currentSegment = 0;
  try {
    currentSegment = data.getName().get(-1).toSegment();
  }
  catch (ex) {
    Pipeline.reportError(this.onError, Pipeline.ErrorCode.DATA_HAS_NO_SEGMENT,
                         "Error decoding the name segment number " +
                         data.getName().get(-1).toEscapedString() + ": " + ex);
    return;
  }

  // set finalBlockId
  if (data.getMetaInfo().getFinalBlockId().getValue().size() > 0) {
    try {
      this.finalBlockId = data.getMetaInfo().getFinalBlockId().toSegment();
      this.cancelPendingInterestsAboveFinalBlockId();
    }
    catch (ex) {
      Pipeline.reportError(this.onError, Pipeline.ErrorCode.DATA_HAS_NO_SEGMENT,
           "Error decoding the FinalBlockId segment number " +
            data.getMetaInfo().getFinalBlockId().toEscapedString() +
            ": " + ex);
      return;
    }
  }

  this.numberOfSatisfiedSegments += 1;

  // Save the content
  this.contentParts[currentSegment] = data.getContent().buf();

  // Check whether we are finished
  if (this.numberOfSatisfiedSegments > this.finalBlockId) {
    // Concatenate to get content.
    var content = Buffer.concat(this.contentParts);
    try {
      this.onComplete(new Blob(content, false));
    } catch (ex) {
      console.log("Error in onComplete: " + NdnCommon.getErrorWithStackTrace(ex));
    }

    return;
  }

  this.decreaseNumberOfSegmentsOnFly();

  // Fetch the next segments
  this.fetchNextSegments(originalInterest, data.getName());
};

PipelineFixed.prototype.onValidationFailed = function(data, reason)
{
  Pipeline.reportError(this.onError, Pipeline.ErrorCode.SEGMENT_VERIFICATION_FAILED,
                       "Segment verification failed for " + data.getName().toUri() +
                       " . Reason: " + reason);
};

PipelineFixed.prototype.onTimeout = function(interest)
{
  Pipeline.reportError(this.onError, Pipeline.ErrorCode.INTEREST_TIMEOUT,
                       "Time out for interest " + interest.getName().toUri());
};

PipelineFixed.prototype.onNack = function(interest)
{
  Pipeline.reportError(this.onError, Pipeline.ErrorCode.NACK_RECEIVED,
                       "Received Nack for interest " + interest.getName().toUri());
};

PipelineFixed.prototype.increaseNumberOfSegmentsOnFly = function()
{
  this.segmentsOnFly++;
};

PipelineFixed.prototype.decreaseNumberOfSegmentsOnFly = function()
{
  this.segmentsOnFly = Math.max(this.segmentsOnFly - 1, 0);
};

PipelineFixed.prototype.reportError = function(errCode, msg)
{
  try {
    this.onError(errCode, msg);
  } catch (ex) {
    console.log("Error in onError: " + NdnCommon.getErrorWithStackTrace(ex));
  }
};
