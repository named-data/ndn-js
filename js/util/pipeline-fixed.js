/**
 * Copyright (C) 2013 Regents of the University of California.
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
var LOG = require('../log.js').Log.LOG;


/**
 * Retrieve the segments of solicited data by keeping a fixed-size window of N
 * of on fly Interests at any given time.
 *
 * To handle timeout and nack we use DataFetcher class which upon facing
 * timeout or nack will try to resolve the corresponded segment by retransmitting
 * the Interest a few times.
 *
 * PipelineFixed assumes that the data is named /<prefix>/<version>/<segment>,
 * where:
 * - <prefix> is the specified name prefix,
 * - <version> is an unknown version that needs to be discovered, and
 * - <segment> is a segment number. (The number of segments is unknown and is
 *   controlled by the `FinalBlockId` field in at least the last Data packet.
 *
 * The following logic is implemented in PipelineFixed:
 *
 * 1. Express the first Interest to discover the version:
 *
 *    >> Interest: /<prefix>?MustBeFresh=true
 *
 * 2. Infer the latest version of the Data: <version> = Data.getName().get(-2)
 *
 * 3. If the segment number in the retrieved packet == 0, go to step 5.
 *
 * 4. Pipeline the Interets starting from segment 0:
 *
 *    >> Interest: /<prefix>/<version>/<segment=0>
 *    >> Interest: /<prefix>/<version>/<segment=1>
 *    ...
 *    >> Interest: /<prefix>/<version>/<segment=this.windowSize-1>
 *
 * At any given time the number of on the fly Interests should be equal
 * to this.windowSize.
 *
 * 5. Pipeline the Interests startging from segment 1.
 *
 *    >> Interest: /<prefix>/<version>/<segment=1>
 *    >> Interest: /<prefix>/<version>/<segment=2>
 *    ...
 *    >> Interest: /<prefix>/<version>/<segment=this.windowSize>
 *
 * 6. Upon receving a valid Data back we pipeline an Interest for the
 * next expected segment.
 *
 *    >> Interest: /<prefix>/<version>/<segment=(N+1))>
 *
 * We repeat step 6 until the retrieved Data does not have a FinalBlockId
 * or the FinalBlockId != Data.getName().get(-1).
 *
 * 7. Call the onComplete callback with a Blob that concatenates the content
 *    from all the segmented objects.
 *
 * If an error occurs during the fetching process, the onError callback is called
 * with a proper error code.  The following errors are possible:
 *
 * - `INTEREST_TIMEOUT`: if any of the Interests times out (probably after a number of retries)
 * - `DATA_HAS_NO_SEGMENT`: if any of the retrieved Data packets don't have a segment
 *   as the last component of the name (not counting the implicit digest)
 * - `SEGMENT_VERIFICATION_FAILED`: if any retrieved segment fails
 *   the user-provided VerifySegment callback or KeyChain verifyData.
 * - `IO_ERROR`: for I/O errors when sending an Interest.
 * -`DUPLICATE_SEGMENT_RECEIVED`: if any duplicate segment is receveid during
 *   fetching the data (we do not ask for a segment that is already retrieved,
 *   again)
 *
 * In order to validate individual segments, a KeyChain needs to be supplied.
 * If verifyData fails, the fetching process is aborted with
 * SEGMENT_VERIFICATION_FAILED. If data validation is not required, pass null.
 *
 *
 * This is a public constructor to create a new PipelineFixed.
 * If validatorKeyChain is not null, use it and ignore verifySegment.
 * @param {string} basePrefix This is the prefix of the data we want to retreive
 * its segments (excluding <version> and <segment> components).
 * @param {Face} face The segments will be fetched through this face.
 * @param {KeyChain} validatorKeyChain If this is not null, use its verifyData
 * instead of the verifySegment callback.
 * @param {function} verifySegment When a Data packet is received this calls
 * verifySegment(data) where data is a Data object. If it returns false then
 * abort fetching and call onError with
 * PipelineFixed.ErrorCode.SEGMENT_VERIFICATION_FAILED.
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onComplete When all segments are received, call
 * onComplete(content) where content is a Blob which has the concatenation of
 * the content of all the segments.
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onError Call onError.onError(errorCode, message) for
 * timeout or an error processing segments. errorCode is a value from
 * PipelineFixed.ErrorCode and message is a related string.
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @constructor
 */
var PipelineFixed = function PipelineFixed
  (basePrefix, face, validatorKeyChain, verifySegment, onComplete, onError)
{
  this.contentPrefix = basePrefix;
  this.face = face;
  this.validatorKeyChain = validatorKeyChain;
  this.verifySegment = verifySegment;
  this.onComplete = onComplete;
  this.onError = onError;

  this.contentParts = []; // of Buffer

  this.satisfiedSegments = []; // no duplicate entry
  this.nextSegmentToRequest = 0;
  this.firstSegmentIsReceived = false;
  this.finalBlockNo = -1;

  // Options
  this.windowSize = 10;
  this.maxTimeoutRetries = 3;
  this.maxNackRetries = 3;

  this.segmentsOnFly = 0;

  // Stats
  this.onVerifiedDelay = 0;
  this.sendInterestDelay = 0;
  this.onDataDelay = 0;
  this.pipelineDelay = 0;

  this.pipelineStartTime = Date.now();
};

exports.PipelineFixed = PipelineFixed;

/**
 * An ErrorCode value is passed in the onError callback.
 */
PipelineFixed.ErrorCode = {
  INTEREST_TIMEOUT: 1,
  DATA_HAS_NO_SEGMENT: 2,
  SEGMENT_VERIFICATION_FAILED: 3,
  DUPLICATE_SEGMENT_RECEIVED: 4,
  NACK_RECEIVED: 5
};

/**
 * Use DataFetcher to fetch the solicited segment. Timeouts and Nacks will be
 * handled by DataFetcher class.
 */
PipelineFixed.prototype.fetchSegment = function(interest)
{
  var df = new DataFetcher
    (this, this.face, interest, this.maxNackRetries, this.maxTimeoutRetries, this.onData, this.onNack, this.onTimeout);
  df.fetch();
};

PipelineFixed.prototype.fetchFirstSegment = function(baseInterest)
{
  var interest = new Interest(baseInterest);
  interest.setMustBeFresh(true);
  var thisPipeline = this;

  this.fetchSegment(interest);
};

PipelineFixed.prototype.fetchNextSegments = function
  (originalInterest, dataName)
{
  var sTime = Date.now();
  // Changing a field clears the nonce so that a new none will be generated
  if (this.firstSegmentIsReceived === false) {
    console.log("First segment is not received yet");
    return;
  }

  var interest = new Interest(originalInterest);
  interest.setMustBeFresh(false);

  while (this.nextSegmentToRequest <= this.finalBlockNo && this.segmentsOnFly <= this.windowSize) {
    // Start with the original Interest to preserve any special selectors.
    interest.setName(dataName.getPrefix(-1).appendSegment(this.nextSegmentToRequest));
    interest.refreshNonce();

    var thisPipeline = this;

    this.fetchSegment(interest);

    this.nextSegmentToRequest += 1;
    this.increaseNumberOfSegmentsOnFly;
  }
  this.sendInterestDelay += ((Date.now() - sTime)/1000);
};

PipelineFixed.prototype.onData = function(originalInterest, data)
{
  var sTime = Date.now();

  if (this.validatorKeyChain != null) {
    try {
      var thisPipeline = this;
      this.validatorKeyChain.verifyData
        (data,
         function(localData) {
           thisPipeline.onVerified(localData, originalInterest);
         },
         this.onValidationFailed.bind(this));
    } catch (ex) {
      console.log("Error in KeyChain.verifyData: " + ex);
    }
  }
  else {
    if (!this.verifySegment(data)) {
      this.reportError(PipelineFixed.ErrorCode.SEGMENT_VERFIFICATION_FAILED,
                       "Segment verification failed");
    }

    this.onDataDelay += ((Date.now() - sTime)/1000);
    this.onVerified(data, originalInterest);
  }
};

PipelineFixed.prototype.onVerified = function(data, originalInterest)
{
  var sTime = Date.now();
  var currentSegment = 0;

  if (!PipelineFixed.endsWithSegmentNumber(data.getName())) {
    // We don't expect a name without a segment number.  Treat it as a bad packet.
    this.reportError(PipelineFixed.ErrorCode.DATA_HAS_NO_SEGMENT,
                     "Got an unexpected packet without a segment number: " +
                      data.getName().toUri());
  }
  else {
    try {
      currentSegment = data.getName().get(-1).toSegment();
    }
    catch (ex) {
      this.reportError(PipelineFixed.ErrorCode.DATA_HAS_NO_SEGMENT,
                       "Error decoding the name segment number " +
                       data.getName().get(-1).toEscapedString() + ": " + ex);
      return;
    }
  }

  // Check for first segment
  if (this.firstSegmentIsReceived === false) {
    this.firstSegmentIsReceived = true;
    if (currentSegment === 0) {
      this.nextSegmentToRequest += 1;
    }
  }

  if (data.getMetaInfo().getFinalBlockId().getValue().size() > 0) {
    try {
      this.finalBlockNo = (data.getMetaInfo().getFinalBlockId().toSegment());
    }
    catch (ex) {
      this.reportError(PipelineFixed.ErrorCode.DATA_HAS_NO_SEGMENT,
           "Error decoding the FinalBlockId segment number " +
            data.getMetaInfo().getFinalBlockId().toEscapedString() +
            ": " + ex);
      return;
    }
  }

  if (this.isDuplicateSegment(currentSegment)) {
    console.log('Error: duplicate satisfied segment [' + currentSegment + ']');
    return;
  }
  this.satisfiedSegments.push(currentSegment);

  // Save the content
  this.contentParts[currentSegment] = data.getContent().buf();

  // Check whether we are finished
  if (this.satisfiedSegments.length >= this.finalBlockNo + 1) {
    // Concatenate to get content.
    var content = Buffer.concat(this.contentParts);
    try {
      this.onComplete(new Blob(content, false));
    } catch (ex) {
      console.log("Error in onComplete: " + NdnCommon.getErrorWithStackTrace(ex));
    }
    this.pipelineDelay = (Date.now() - this.pipelineStartTime)/1000;

    if (LOG > 3) {
      console.log('Pipeline retrieval delay:  ',  this.pipelineDelay);
      console.log('Total sending Interests delay: ', this.sendInterestDelay);
      console.log('Total Data verification delay: ', this.onVerifiedDelay);
      console.log('Total handling Data delay: ', this.onDataDelay);
    }
    return;
  }

  this.decreaseNumberOfSegmentsOnFly();
  this.onVerifiedDelay += (Date.now() - sTime)/1000;

  // Fetch the next segments
  this.fetchNextSegments
    (originalInterest, data.getName());
};

PipelineFixed.prototype.onValidationFailed = function(data, reason)
{
  this.reportError(PipelineFixed.ErrorCode.SEGMENT_VERIFICATION_FAILED,
                   "Segment verification failed for " + data.getName().toUri() +
                   " . Reason: " + reason);
};

PipelineFixed.prototype.onTimeout = function(interest)
{
  this.reportError(PipelineFixed.ErrorCode.INTEREST_TIMEOUT,
                   "Time out for interest " + interest.getName().toUri());
};

PipelineFixed.prototype.onNack = function(interest)
{
  this.reportError(PipelineFixed.ErrorCode.NACK_RECEIVED,
                   "Received Nack for interest " + interest.getName().toUri());
};

PipelineFixed.prototype.increaseNumberOfSegmentsOnFly = function()
{
  this.segmentsOnFly++;
};

PipelineFixed.prototype.decreaseNumberOfSegmentsOnFly = function()
{
  this.segmentsOnFly = (this.segmentsOnFly <= 0) ? 0
    : this.segmentsOnFly - 1;
};

PipelineFixed.prototype.reportError = function(errCode, msg)
{
  try {
    this.onError(errCode, msg);
  } catch (ex) {
    console.log("Error in onError: " + NdnCommon.getErrorWithStackTrace(ex));
  }
};

PipelineFixed.prototype.isDuplicateSegment = function (segment)
{
  for (var i = 0, len = this.satisfiedSegments.length; i < len; i++) {
    if (segment === this.satisfiedSegments[i])
      return true;
  }
  return false;
};

/**
 * Check if the last component in the name is a segment number.
 * @param {Name} name The name to check.
 * @return {boolean} True if the name ends with a segment number, otherwise false.
 */
PipelineFixed.endsWithSegmentNumber = function(name)
{
  return name.size() >= 1 && name.get(-1).isSegment();
};
