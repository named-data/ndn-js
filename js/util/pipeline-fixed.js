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
var NdnCommon = require('./ndn-common.js').NdnCommon; /** @ignore */
var RttEstimator = require('./rtt-estimator.js').RttEstimator; /** @ignore */
var DataFetcher = require('./data-fetcher.js').DataFetcher; /** @ignore */
var Pipeline = require('./pipeline.js').Pipeline;
var LOG = require('../log.js').Log.LOG;

/**
 * Retrieve the segments of solicited data by keeping a fixed-size window of N
 * of in fly Interests at any given time.
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
 * with a proper error code (see Pipeline documentation).
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
 * NOTE: The library will log any exceptions thrown by this callback, but for better error handling the
 *       callback should catch and properly handle any exceptions.
 * @param {function} onError Call onError(errorCode, message) for any error during content retrieval
 *                           (see Pipeline documentation for ful list of errors).
 * NOTE: The library will log any exceptions thrown by this callback, but for better error handling the
 *       callback should catch and properly handle any exceptions.
 * @param {Object} stats An object that exposes statistics of content retrieval performance to caller.
 * @constructor
 */
var PipelineFixed = function PipelineFixed
  (baseInterest, face, opts, validatorKeyChain, onComplete, onError, stats)
{
  this.face = face;
  this.validatorKeyChain = validatorKeyChain;
  this.onComplete = onComplete;
  this.onError = onError;
  this.pipeline = new Pipeline(baseInterest);

  this.nInFlight = 0;

  // Options
  this.windowSize = Pipeline.op("windowSize", 10, opts);
  this.maxRetriesOnTimeoutOrNack = Pipeline.op("maxRetriesOnTimeoutOrNack", 3, opts);

  this.segmentInfo = []; // track information that is necessary for segment transmission.
                         // If a segment experienced retransmission its status will
                         // be `retx`, otherwise `normal`
  this.dataFetchersContainer = []; // if we need to cancel pending interests

  this.rttEstimator = new RttEstimator(opts);

  // Stats collector
  this.stats = stats != null ? stats : {};
  this.stats.nTimeouts      = 0;
  this.stats.nNacks         = 0;
  this.stats.nRetransmitted = 0;
};

exports.PipelineFixed = PipelineFixed;

PipelineFixed.prototype.run = function()
{
  var interest = this.pipeline.makeInterest(0);
  if (Number.isNaN(this.pipeline.versionNo) ) {
    interest.setMustBeFresh(true);
  }
  else {
    interest.setMustBeFresh(false);
  }

  this.sendInterest(interest);
};

/**
 * Use DataFetcher to fetch the solicited segment. Timeouts and Nacks will be
 * handled by DataFetcher class.
 */
PipelineFixed.prototype.sendInterest = function(interest)
{
  if (this.pipeline.isStopped)
    return;

  if (this.pipeline.hasFailure)
    return;
  var segmentNo = 0;
  if (interest.getName().components.length > 0 && interest.getName().get(-1).isSegment()) {
    segmentNo = interest.getName().get(-1).toSegment();
    this.dataFetchersContainer[segmentNo] = new DataFetcher
      (this.face, interest, this.maxRetriesOnTimeoutOrNack,
       this.handleData.bind(this), this.handleFailure.bind(this),
       this.segmentInfo, this.stats);
       this.dataFetchersContainer[segmentNo].fetch();
  }
  else { // this is the very first interest
    this.dataFetchersContainer[segmentNo] = new DataFetcher
      (this.face, interest, this.maxRetriesOnTimeoutOrNack,
       this.handleData.bind(this), this.handleFailure.bind(this),
       this.segmentInfo, this.stats);
       this.dataFetchersContainer[segmentNo].fetch();
  }
};

PipelineFixed.prototype.sendNextInterests = function()
{
  if (this.pipeline.isStopped)
    return;

  while (this.pipeline.nextSegmentNo <= this.pipeline.finalBlockId && this.nInFlight <= this.windowSize) {
    // do not re-send an interest for existing segments
    if (this.pipeline.contentParts[this.pipeline.nextSegmentNo] !== undefined) {
      this.pipeline.getNextSegmentNo();
      continue;
    }

    var interest = this.pipeline.makeInterest(this.pipeline.getNextSegmentNo());
    // Changing a field clears the nonce so that a new nonce will be generated
    interest.setMustBeFresh(false);
    interest.refreshNonce();

    this.sendInterest(interest);
    this.nInFlight++;
  }
};

PipelineFixed.prototype.cancelInFlightSegmentsGreaterThan = function(segNo)
{
  var len = this.dataFetchersContainer.length;

  for (var i = segNo + 1; i < len; ++i) {
    if (this.dataFetchersContainer[i] !== null) {
      this.face.removePendingInterest(this.dataFetchersContainer[i].getPendingInterestId());
    }
  }
};

PipelineFixed.prototype.handleData = function(interest, data)
{
  if (this.validatorKeyChain !== null) {
    try {
      var thisPipeline = this;
      this.validatorKeyChain.verifyData
        (data,
         function(localData) {
           thisPipeline.onData(localData);
         },
         this.onValidationFailed.bind(this));
    }
    catch (ex) {
      Pipeline.reportError(this.onError, Pipeline.ErrorCode.SEGMENT_VERIFICATION_FAILED,
                           "Error in KeyChain.verifyData: " + ex);
      return;
    }
  }
  else {
    this.onData(data);
  }
};

PipelineFixed.prototype.onData = function(data)
{
  if (this.pipeline.isStopped)
    return;

  var recSegmentNo = 0;
  try {
    recSegmentNo = data.getName().get(-1).toSegment();
  }
  catch (ex) {
    this.handleFailure(recSegmentNo, Pipeline.ErrorCode.DATA_HAS_NO_SEGMENT,
                       "Error while decoding the segment number " +
                       data.getName().get(-1).toEscapedString() + ": " + ex);
    return;
  }

  if (Number.isNaN(this.pipeline.versionNo)) {
    try {
      this.pipeline.versionNo = data.getName().get(-2).toVersion();
    }
    catch (ex) {
      this.handleFailure(recSegmentNo, Pipeline.ErrorCode.DATA_HAS_NO_VERSION,
                          "Error while decoding the version number " +
                          data.getName().get(-2).toEscapedString() + ": " + ex);
      return;
    }
  }

  // set finalBlockId
  if (data.getMetaInfo().getFinalBlockId().getValue().size() > 0) {
    try {
      this.pipeline.finalBlockId = data.getMetaInfo().getFinalBlockId().toSegment();
      this.cancelInFlightSegmentsGreaterThan(this.pipeline.finalBlockId);
    }
    catch (ex) {
      Pipeline.reportError(this.onError, Pipeline.ErrorCode.DATA_HAS_NO_SEGMENT,
           "Error while decoding the FinalBlockId field " +
            data.getMetaInfo().getFinalBlockId().toEscapedString() +
            ": " + ex);
      return;
    }
    this.pipeline.hasFinalBlockId = true;
  }

  // Save the content
  this.pipeline.contentParts[recSegmentNo] = data.getContent().buf();

  if (this.pipeline.hasFailure && this.pipeline.hasFinalBlockId) {
    if(this.pipeline.finalBlockId >= this.pipeline.failedSegNo) {
      // Previously failed segment is part of the content
      return this.pipeline.onFailure(this.pipeline.failureErrorCode,
                                     this.pipeline.failureReason,
                                     this.onError);
    }
    else {
      this.pipeline.hasFailure = false;
    }
  }

  var recSeg = this.segmentInfo[recSegmentNo];
  if (recSeg === undefined) {
    return; // ignore an already-received segment
  }

  var rtt = Date.now() - recSeg.timeSent;
  var fullDelay = Date.now() - recSeg.initTimeSent;

  if (LOG > 1) {
    console.log ("Received segment #" + recSegmentNo
                 + ", rtt=" + rtt + "ms"
                 + ", rto=" + recSeg.rto + "ms");
  }

  // Do not sample RTT for retransmitted segments
  if (this.segmentInfo[recSegmentNo].stat === "normal") {
    var nExpectedSamples = Math.max((this.nInFlight + 1) >> 1, 1);
    if (nExpectedSamples <= 0) {
      this.handleFailure(-1, Pipeline.ErrorCode.MISC, "nExpectedSamples is less than or equal to ZERO.");
    }
    this.rttEstimator.addMeasurement(recSegmentNo, rtt, nExpectedSamples);
    this.rttEstimator.addDelayMeasurement(recSegmentNo, Math.max(rtt, fullDelay));
  }
  else { // Sample the retrieval delay to calculate jitter
    this.rttEstimator.addDelayMeasurement(recSegmentNo, Math.max(rtt, fullDelay));
  }

  this.pipeline.numberOfSatisfiedSegments++;

  // Check whether we are finished
  if (this.pipeline.hasFinalBlockId &&
      this.pipeline.numberOfSatisfiedSegments > this.pipeline.finalBlockId) {
    // Concatenate to get content.
    var content = Buffer.concat(this.pipeline.contentParts);
    this.cancelInFlightSegmentsGreaterThan(this.pipeline.finalBlockId);
    this.stats.avgRtt    = this.rttEstimator.getAvgRtt().toPrecision(3),
    this.stats.avgJitter = this.rttEstimator.getAvgJitter().toPrecision(3),
    this.stats.nSegments = this.pipeline.numberOfSatisfiedSegments;
    try {
      this.pipeline.cancel();
      this.onComplete(new Blob(content, false));
    }
    catch (ex) {
      console.log("Error in onComplete: " + NdnCommon.getErrorWithStackTrace(ex));
      return;
    }
    return;
  }

  this.nInFlight = Math.max(this.nInFlight - 1, 0);

  // Send next Interests
  this.sendNextInterests();
};

/**
 * @param segNo the segment for which a failure happened
 * @note if segNo is `-1` it means a general failure happened
 *       (e.g., negative number of in flight segments)
 * @param errCode comes from Pipeline.ErrorCode
 * @param reason a description about the failure
 */
PipelineFixed.prototype.handleFailure = function(segNo, errCode, reason)
{
  if (this.pipeline.isStopped)
    return;

  // this is a general failure; not specific to one segment
  if (segNo === -1) {
    this.pipeline.onFailure(errCode, reason, this.onError);
    return;
  }

  // if the failed segment is definitely part of the content, raise a fatal error
  if (segNo === 0 || (this.pipeline.hasFinalBlockId && segNo <= this.pipeline.finalBlockId))
    return this.pipeline.onFailure(errCode, reason, this.onError);

  if (!this.pipeline.hasFinalBlockId) {
    this.nInFlight--;

    if (this.nInFlight <= 0) {
      this.pipeline.onFailure(Pipeline.ErrorCode.NO_FINALBLOCK,
                              "Fetching terminated at segment " + segNo +
                              " but no finalBlockId has been found",
                              this.onError);
    }
    else {
      this.cancelInFlightSegmentsGreaterThan(segNo);
      this.pipeline.hasFailure = true;
      this.pipeline.failedSegNo = segNo;
      this.pipeline.failureErrorCode = errCode;
      this.pipeline.failureReason = reason;
    }
  }
};

PipelineFixed.prototype.onValidationFailed = function(data, reason)
{
  Pipeline.reportError(this.onError, Pipeline.ErrorCode.SEGMENT_VERIFICATION_FAILED,
                       "Segment verification failed for " + data.getName().toUri() +
                       " . Reason: " + reason);
};
