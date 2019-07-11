/**
 * Copyright (C) 2018-2019 Regents of the University of California.
 * @author: Chavoosh Ghasemi <chghasemi@cs.arizona.edu>
 * @author: From https://github.com/named-data/ndn-tools/tree/master/tools/chunks
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
var Name = require('../name.js').Name; /** @ignore */
var Blob = require('./blob.js').Blob; /** @ignore */
var KeyChain = require('../security/key-chain.js').KeyChain; /** @ignore */
var NdnCommon = require('./ndn-common.js').NdnCommon; /** @ignore */
var RttEstimator = require('./rtt-estimator.js').RttEstimator; /** @ignore */
var Pipeline = require('./pipeline.js').Pipeline; /** @ignore */
var LOG = require('../log.js').Log.LOG;

/**
 * Implementation of Cubic pipeline according to:
 *   [RFC8312](https://tools.ietf.org/html/rfc8312)
 *   [Linux kernel implementation](https://github.com/torvalds/linux/blob/master/net/ipv4/tcp_cubic.c)
 *   [ndnchunks tool bundle](https://github.com/named-data/ndn-tools/tree/master/tools/chunks)
 *
 * This is a public constructor to create a new PipelineCubic.
 * @param {Interest} baseInterest This interest should be well-formed to represent all necessary fields
 *                                that the application wants to use for all Interests (e.g., interest
 *                                lifetime).
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
var PipelineCubic = function PipelineCubic
  (baseInterest, face, opts, validatorKeyChain, onComplete, onError, stats)
{
  this.pipeline = new Pipeline(baseInterest);
  this.face = face;
  this.validatorKeyChain = validatorKeyChain;
  this.onComplete = onComplete;
  this.onError = onError;

  // Adaptive options
  this.initCwnd = Pipeline.op("initCwnd", 1.0, opts);
  this.cwnd = Pipeline.op("cwnd", this.initCwnd, opts);
  this.ssthresh = Pipeline.op("ssthresh", Number.MAX_VALUE, opts);
  this.rtoCheckInterval = Pipeline.op("rtoCheckInterval", 10, opts);
  this.disableCwa = Pipeline.op("disableCwa", false, opts);
  this.maxRetriesOnTimeoutOrNack = Pipeline.op("maxRetriesOnTimeoutOrNack", 3, opts);

  // Cubic options
  this.enableFastConv = Pipeline.op("enableFastConv", false, opts);
  this.cubicBeta = Pipeline.op("cubicBeta", 0.7, opts);
  this.wmax = Pipeline.op("wmax", 0, opts); // window size before last window decrease
  this.lastWmax = Pipeline.op("lastWmax", 0, opts); // last wmax
  this.lastDecrease = Date.now(); // time of last window decrease
  this.cubic_c = 0.4;

  // Run options
  this.highData = 0;       // the highest segment number of the Data packet the consumer has received so far
  this.highInterest = 0;   // the highest segment number of the Interests the consumer has sent so far
  this.recPoint = 0;       // the value of highInterest when a packet loss event occurred,
                           // it remains fixed until the next packet loss event happens
  this.nInFlight = 0;      // # of segments in flight
  this.nLossDecr = 0;      // # of window decreases caused by packet loss
  this.nTimeouts = 0;      // # of timed out segments
  this.nNacks = 0;         // # of nack segments
  this.nSkippedRetx = 0;   // # of segments queued for retransmission but received before
                           // retransmission occurred
  this.nRetransmitted = 0; // # of retransmitted segments
  this.nSent = 0;          // # of interest packets sent out (including retransmissions)
  this.segmentInfo = [];   // track information that is necessary for segment transmission
  this.retxQueue = [];     // a queue to store segments that need to retransmitted
  this.retxCount = [];     // track number of retx of each segment

  this.rttEstimator = new RttEstimator(opts);

  // Stats collector
  this.stats = stats != null ? stats : {};
}

exports.PipelineCubic = PipelineCubic;

PipelineCubic.SegmentState = {
  FirstTimeSent: 1, // segment has been sent for the first time
  InRetxQueue: 2,   // segment is in retransmission queue
  Retransmitted: 3  // segment has been retransmitted
};

PipelineCubic.prototype.increaseWindow = function()
{
  // Slow start phase
  if (this.cwnd < this.ssthresh) {
    this.cwnd += 1;
  }
  // Congestion avoidance phase
  else {
    // If wmax is still 0, set it to the current cwnd. Usually unnecessary,
    // if m_ssthresh is large enough.
    if (this.wmax < this.initCwnd) {
      this.wmax = this.cwnd;
    }

    // 1. Time since last congestion event in seconds
    var t = (Date.now() - this.lastDecrease) / 1000;

    // 2. Time it takes to increase the window to wmax
    var k = Math.cbrt(this.wmax * (1 - this.cubicBeta) / this.cubic_c);

    // 3. Target: W_cubic(t) = C*(t-K)^3 + wmax (Eq. 1)
    var wCubic = this.cubic_c * Math.pow(t - k, 3) + this.wmax;

    // 4. Estimate of Reno Increase (Currently Disabled)
    var wEst = 0.0;

    // Actual adaptation
    var cubicIncrement = Math.max(wCubic, wEst) - this.cwnd;
    // Cubic increment must be positive
    // Note: This change is not part of the RFC, but it is added performance improvement
    cubicIncrement = Math.max(0, cubicIncrement);

    this.cwnd += cubicIncrement / this.cwnd;
  }
};

PipelineCubic.prototype.decreaseWindow = function()
{
  // A flow remembers the last value of wmax,
  // before it updates wmax for the current congestion event.

  // Current wmax < last_wmax
  if (this.enableFastConv && this.cwnd < this.lastWmax) {
    this.lastWmax = this.cwnd;
    this.wmax = this.cwnd * (1.0 + this.cubicBeta) / 2.0;
  }
  else {
    // Save old cwnd as wmax
    this.lastWmax = this.cwnd;
    this.wmax = this.cwnd;
  }

  this.ssthresh = Math.max(this.initCwnd, this.cwnd * this.cubicBeta);
  this.cwnd = this.ssthresh;
  this.lastDecrease = Date.now();
};

PipelineCubic.prototype.run = function()
{
  // Schedule the next check after the predefined interval
  setTimeout(this.checkRto.bind(this), this.rtoCheckInterval);

  this.sendInterest(this.pipeline.getNextSegmentNo(), false);
};

PipelineCubic.prototype.cancel = function()
{
  this.pipeline.cancel();
  this.segmentInfo.length = 0;
};

/**
 * @param segNo to-be-sent segment number
 * @param isRetransmission true if this is a retransmission
 */
PipelineCubic.prototype.sendInterest = function(segNo, isRetransmission)
{
  if (this.pipeline.isStopped)
    return;

  if (this.pipeline.hasFinalBlockId && segNo > this.pipeline.finalBlockId)
    return;

  if (!isRetransmission && this.pipeline.hasFailure)
    return;

  if (isRetransmission) {
    // keep track of retx count for this segment
    if (this.retxCount[segNo] === undefined) {
      this.retxCount[segNo] = 1;
    }
    else { // not the first retransmission
      this.retxCount[segNo]++;
      if (this.retxCount[segNo] > this.maxRetriesOnTimeoutOrNack) {
        return this.handleFailure(segNo, Pipeline.ErrorCode.MAX_NACK_TIMEOUT_RETRIES,
            "Reached the maximum number of retries (" +
             this.maxRetriesOnTimeoutOrNack + ") while retrieving segment #" + segNo);
      }
    }
    if (LOG > 1)
      console.log("Retransmitting segment #" + segNo + " (" + this.retxCount[segNo] + ")");
  }

  if (LOG > 1 && !isRetransmission)
    console.log("Requesting segment #" + segNo);

  var interest = this.pipeline.makeInterest(segNo);

  if (Number.isNaN(this.pipeline.versionNo) ) {
    interest.setMustBeFresh(true);
  }
  else {
    interest.setMustBeFresh(false);
  }

  var segInfo = {};
  segInfo.pendingInterestId = this.face.expressInterest
    (interest,
     this.handleData.bind(this),
     this.handleLifetimeExpiration.bind(this),
     this.handleNack.bind(this));

  // initTimeSent allows calculating full delay
  if (isRetransmission && segInfo.initTimeSent === undefined)
    segInfo.initTimeSent = segInfo.timeSent;

  segInfo.timeSent = Date.now();
  segInfo.rto = this.rttEstimator.getEstimatedRto();

  this.nInFlight++;
  this.nSent++;

  if (isRetransmission) {
    segInfo.state = PipelineCubic.SegmentState.Retransmitted;
    this.nRetransmitted++;
  }
  else {
    this.highInterest = segNo;
    segInfo.state = PipelineCubic.SegmentState.FirstTimeSent;
  }
  this.segmentInfo[segNo] = segInfo;
};

PipelineCubic.prototype.schedulePackets = function()
{
  if (this.nInFlight < 0) {
    this.handleFailure(-1, Pipeline.ErrorCode.MISC, "Number of in flight Interests is negative.");
    return;
  }

  var availableWindowSize = this.cwnd - this.nInFlight;

  while (availableWindowSize > 0) {
    if (this.retxQueue.length != 0) { // do retransmission first
      var retxSegNo = this.retxQueue.shift();
      if (this.segmentInfo[retxSegNo] === undefined) {
        this.nSkippedRetx++;
        continue;
      }
      // the segment is still in the map, that means it needs to be retransmitted
      this.sendInterest(retxSegNo, true);
    }
    else { // send next segment
      this.sendInterest(this.pipeline.getNextSegmentNo(), false);
    }
    availableWindowSize--;
  }
};

PipelineCubic.prototype.handleData = function(interest, data)
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

PipelineCubic.prototype.onData = function(data)
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
  if (!this.pipeline.hasFinalBlockId && data.getMetaInfo().getFinalBlockId().getValue().size() > 0) {
    try {
      this.pipeline.finalBlockId = data.getMetaInfo().getFinalBlockId().toSegment();
    }
    catch (ex) {
      this.handleFailure(recSegmentNo, Pipeline.ErrorCode.DATA_HAS_NO_SEGMENT,
                         "Error while decoding FinalBlockId field " +
                         data.getName().get(-1).toEscapedString() + ": " + ex);
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
                                     this.onError,
                                     this.cancel.bind(this));
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
  var fullDelay = 0;
  if (recSeg.initTimeSent !== undefined)
    fullDelay = Date.now() - recSeg.initTimeSent;

  if (LOG > 1) {
    console.log ("Received segment #" + recSegmentNo
                 + ", rtt=" + rtt + "ms"
                 + ", rto=" + recSeg.rto + "ms");
  }

  if (this.highData < recSegmentNo) {
    this.highData = recSegmentNo;
  }

  // For segments in retx queue, we must not decrement nInFlight
  // because it was already decremented when the segment timed out
  if (recSeg.state !== PipelineCubic.SegmentState.InRetxQueue) {
    this.nInFlight--;
  }

  // Do not sample RTT for retransmitted segments
  if ((recSeg.state === PipelineCubic.SegmentState.FirstTimeSent ||
       recSeg.state === PipelineCubic.SegmentState.InRetxQueue) &&
      this.retxCount[recSegmentNo] === undefined) {
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

  // Clear the entry associated with the received segment
  this.segmentInfo[recSegmentNo] = undefined;  // do not splice

  this.pipeline.numberOfSatisfiedSegments++;

  // Check whether we are finished
  if (this.pipeline.hasFinalBlockId &&
      this.pipeline.numberOfSatisfiedSegments > this.pipeline.finalBlockId) {
    // Concatenate to get the content
    var content = Buffer.concat(this.pipeline.contentParts);
    this.cancelInFlightSegmentsGreaterThan(this.pipeline.finalBlockId);
    // fill out the stats
    this.stats.nTimeouts      = this.nTimeouts;
    this.stats.nNacks         = this.nNacks;
    this.stats.nRetransmitted = this.nRetransmitted;
    this.stats.avgRtt         = this.rttEstimator.getAvgRtt().toPrecision(3);
    this.stats.avgJitter      = this.rttEstimator.getAvgJitter().toPrecision(3);
    this.stats.nSegments      = this.pipeline.numberOfSatisfiedSegments;
    try {
      this.cancel();
      this.printSummary();
      this.onComplete(new Blob(content, false));
    }
    catch (ex) {
      this.handleFailure(-1, Pipeline.ErrorCode.MISC,
           "Error in onComplete: " + NdnCommon.getErrorWithStackTrace(ex));
      return;
    }
    return;
  }

  this.increaseWindow();

  // Schedule the next segments to be fetched
  this.schedulePackets();
};

PipelineCubic.prototype.checkRto = function()
{
  if (this.pipeline.isStopped)
    return;

  var hasTimeout = false;

  for (var i=0; i < this.segmentInfo.length; ++i) {
    if (this.segmentInfo[i] === undefined)
      continue;

    var segInfo = this.segmentInfo[i];
    if (segInfo.state !== PipelineCubic.SegmentState.InRetxQueue) { // skip segments in the retx queue
      var timeElapsed = Date.now() - segInfo.timeSent;
      if (timeElapsed > segInfo.rto) { // timer expired?
        this.nTimeouts++;
        hasTimeout = true;
        this.onWarning(Pipeline.ErrorCode.INTEREST_TIMEOUT, "handle timeout for segment " + i);
        this.enqueueForRetransmission(i);
      }
    }
  }

  if (hasTimeout) {
    this.recordTimeout();
    this.schedulePackets();
  }

  // schedule the next check after the predefined interval
  setTimeout(this.checkRto.bind(this), this.rtoCheckInterval);
};

PipelineCubic.prototype.enqueueForRetransmission = function(segNo)
{
  if (this.nInFlight <= 0) {
    this.handleFailure(-1, Pipeline.ErrorCode.MISC, "Number of in flight Interests <= 0.");
    return;
  }

  this.nInFlight--;
  this.retxQueue.push(segNo);
  this.segmentInfo[segNo].state = PipelineCubic.SegmentState.InRetxQueue;
};

PipelineCubic.prototype.recordTimeout = function()
{
  if (this.disableCwa || this.highData > this.recPoint) {
    // react to only one timeout per RTT (conservative window adaptation)
    this.recPoint = this.highInterest;

    this.decreaseWindow();
    this.rttEstimator.backoffRto();
    this.nLossDecr++;

    if (LOG > 1) {
      console.log("Packet loss event, new cwnd = " + this.cwnd
                  + ", ssthresh = " + this.ssthresh);
    }
  }
};

PipelineCubic.prototype.cancelInFlightSegmentsGreaterThan = function(segNo)
{
  for (var i = segNo + 1; i < this.segmentInfo.length; ++i) {
    // cancel fetching all segments that follow
    if (this.segmentInfo[i] !== undefined)
      this.face.removePendingInterest(this.segmentInfo[i].pendingInterestId);

    this.segmentInfo[i] = undefined;  // do no splice
    this.nInFlight--;
  }
};

/**
 * @param {int} segNo the segment for which a failure happened
 * @note if segNo is `-1` it means a general failure happened
 *       (e.g., negative number of in flight segments)
 * @param {Pipeline.ErrorCode} errCode One of the predefined error codes.
 * @param {string} reason A short description about the error.
 */
PipelineCubic.prototype.handleFailure = function(segNo, errCode, reason)
{
  if (this.pipeline.isStopped)
    return;

  // this is a general failure; not specific to one segment
  if (segNo === -1) {
    this.pipeline.onFailure(errCode, reason, this.onError, this.cancel.bind(this));
    return;
  }

  // if the failed segment is definitely part of the content, raise a fatal error
  if (segNo === 0 || (this.pipeline.hasFinalBlockId && segNo <= this.pipeline.finalBlockId))
    return this.pipeline.onFailure(errCode, reason, this.onError, this.cancel.bind(this));

  if (!this.pipeline.hasFinalBlockId) {
    this.segmentInfo[segNo] = undefined;  // do not splice
    this.nInFlight--;

    var queueIsEmpty = true;
    for (var i = 0; i < this.segmentInfo.length; ++i) {
      if (this.segmentInfo[i] !== undefined) {
        queueIsEmpty = false;
        break;
      }
    }

    if (queueIsEmpty) {
      this.pipeline.onFailure(Pipeline.ErrorCode.NO_FINALBLOCK,
                              "Fetching terminated at segment " + segNo +
                              " but no finalBlockId has been found",
                              this.onError,
                              this.cancel.bind(this));
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

PipelineCubic.prototype.handleLifetimeExpiration = function(interest)
{
  if (this.pipeline.isStopped)
    return;

  this.nTimeouts++;
  var recSegmentNo = 0; // the very first Interest does not have segment number
  // Treated the same as timeout for now
  if (interest.getName().components.length > 0 && interest.getName().get(-1).isSegment())
    recSegmentNo = interest.getName().get(-1).toSegment();

  this.enqueueForRetransmission(recSegmentNo);

  this.onWarning(Pipeline.ErrorCode.INTEREST_LIFETIME_EXPIRATION,
                 "handle interest lifetime expiration for segment " + recSegmentNo);

  this.recordTimeout();
  this.schedulePackets();
};

PipelineCubic.prototype.handleNack = function(interest)
{
  if (this.pipeline.isStopped)
    return;

  this.nNacks++;
  var recSegmentNo = 0; // the very first Interest does not have segment number
  // Treated the same as timeout for now
  if (interest.getName().components.length > 0 && interest.getName().get(-1).isSegment())
    recSegmentNo = interest.getName().get(-1).toSegment();

  this.enqueueForRetransmission(recSegmentNo);

  this.onWarning(Pipeline.ErrorCode.NACK_RECEIVED, "handle nack for segment " + recSegmentNo);

  this.recordTimeout();
  this.schedulePackets();
};

PipelineCubic.prototype.onValidationFailed = function(data, reason)
{
  Pipeline.reportError(this.onError, Pipeline.ErrorCode.SEGMENT_VERIFICATION_FAILED,
                       "Segment verification failed for " + data.getName().toUri() +
                       " . Reason: " + reason);
};

PipelineCubic.prototype.onWarning = function(errCode, reason)
{
  if (LOG > 2) {
    Pipeline.reportWarning(errCode, reason);
  }
};

PipelineCubic.prototype.printSummary = function()
{
  if (LOG < 2)
    return;

  var rttMsg = "";
  if (this.rttEstimator.getMinRtt() === Number.MAX_VALUE ||
      this.rttEstimator.getMaxRtt() === Number.NEGATIVE_INFINITY) {
     rttMsg = "stats unavailable";
   }
   else {
     rttMsg = "min/avg/max = " + this.rttEstimator.getMinRtt().toPrecision(3) + "/"
                                + this.rttEstimator.getAvgRtt().toPrecision(3) + "/"
                                + this.rttEstimator.getMaxRtt().toPrecision(3) + " ms";
  }

  console.log("Timeouts: " + this.nTimeouts + " (caused " + this.nLossDecr + " window decreases)\n" +
              "Nacks: " + this.nNacks + "\n" +
              "Retransmitted segments: " + this.nRetransmitted +
              " (" + (this.nSent == 0 ? 0 : (this.nRetransmitted / this.nSent * 100))  + "%)" +
              ", skipped: " + this.nSkippedRetx + "\n" +
              "RTT " + rttMsg + "\n" +
              "Average jitter: " + this.rttEstimator.getAvgJitter().toPrecision(3) + " ms");
};
