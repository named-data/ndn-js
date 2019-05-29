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
var Name = require('../name.js').Name;
var Blob = require('./blob.js').Blob; /** @ignore */
var KeyChain = require('../security/key-chain.js').KeyChain; /** @ignore */
var NdnCommon = require('./ndn-common.js').NdnCommon;
var RttEstimator = require('./rtt-estimator.js').RttEstimator;
var Pipeline = require('./pipeline.js').Pipeline;
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
var PipelineCubic = function PipelineCubic
  (baseInterest, face, opts, validatorKeyChain, onComplete, onError)
{
  this.baseInterest = baseInterest;
  this.face = face;
  this.validatorKeyChain = validatorKeyChain;
  this.onComplete = onComplete;
  this.onError = onError;
  this.versionNo = NaN; // is discovered from the first received Data packet

  // Adaptive options
  this.initCwnd = Pipeline.op("initCwnd", 1.0, opts);
  this.cwnd = p=Pipeline.op("cwnd", this.initCwnd, opts);
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
  this.nSkippedRetx = 0;   // # of segments queued for retransmission but received before
                           // retransmission occurred
  this.nRetransmitted = 0; // # of retransmitted segments
  this.nSent = 0;          // # of interest packets sent out (including retransmissions)
  this.segmentInfo = [];   // track information that is necessary for segment transmission
  this.retxQueue = [];     // a queue to store segments that need to retransmitted
  this.retxCount = [];     // track number of retx of each segment
  this.isStopped = false;  // false means the pipeline is running
  this.hasFailure = false;
  this.hasFinalBlockId = false;
  this.failedSegNo = 0;
  this.nextSegmentNo = 0;
  this.numberOfSatisfiedSegments = 0;
  this.finalBlockId = Number.MAX_SAFE_INTEGER;

  this.rttEstimator = new RttEstimator(opts);
  this.contentParts = []; // of Buffer (no duplicate entry)
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
  // schedule the next check after predefined interval
  setTimeout(this.checkRto.bind(this), this.rtoCheckInterval);

  this.sendInterest(this.getNextSegmentNo(), false);
};

PipelineCubic.prototype.cancel = function()
{
  if (this.isStopped)
    return;

  this.isStopped = true;
  this.segmentInfo.length = 0;
};

/**
 * @param segNo the segment # of the to-be-sent Interest
 * @param isRetransmission true if this is a retransmission
 */
PipelineCubic.prototype.sendInterest = function(segNo, isRetransmission)
{
  if (this.isStopped)
    return;

  if (this.hasFinalBlockId && segNo > this.finalBlockId)
    return;

  if (!isRetransmission && this.hasFailure)
    return;

  if (isRetransmission) {
    // keep track of retx count for this segment
    if (this.retxCount[segNo] === undefined) {
      this.retxCount[segNo] = 1;
    }
    else { // not the first retransmission
      this.retxCount[segNo]++;
      if (this.retxCount[segNo] > this.maxRetriesOnTimeoutOrNack) {
        return this.handleFail(segNo, Pipeline.ErrorCode.MAX_NACK_TIMEOUT_RETRIES,
            "Reached the maximum number of retries (" +
             this.maxRetriesOnTimeoutOrNack + ") while retrieving segment #" + segNo);
      }
    }
    if (LOG > 1)
      console.log("Retransmitting segment #" + segNo + " (" + this.retxCount[segNo] + ")");
  }

  if (LOG > 1 && !isRetransmission)
    console.log("Requesting segment #" + segNo);


  var interest = new Interest(this.baseInterest);
  if (!Number.isNaN(this.versionNo)) {
    interest.setName(new Name(this.baseInterest.getName())
                     .appendVersion(this.versionNo)
                     .appendSegment(segNo));
  }

  if (segNo === 0) {
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
    console.log("ERROR: Number of in flight Interests is negative");
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
      this.sendInterest(this.getNextSegmentNo(), false);
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
           thisPipeline.onVerified(localData, interest);
         },
         this.onValidationFailed.bind(this));
    } catch (ex) {
      Pipeline.reportError(this.onError, Pipeline.ErrorCode.SEGMENT_VERIFICATION_FAILED,
                           "Error in KeyChain.verifyData: " + ex);
    }
  }
  else {
    this.onData(data);
  }
};

PipelineCubic.prototype.onData = function(data)
{
  if (this.isStopped)
    return;

  var recSegmentNo = 0;

  if (Number.isNaN(this.versionNo)) {
    try {
      this.versionNo = data.getName().get(-2).toVersion();
    }
    catch (ex) {
      this.handleFailure(recSegmentNo, Pipeline.ErrorCode.DATA_HAS_NO_VERSION,
                          "Error decoding the name version number " +
                          data.getName().get(-2).toEscapedString() + ": " + ex);
      return;
    }
  }

  try {
    recSegmentNo = data.getName().get(-1).toSegment();
  }
  catch (ex) {
    this.handleFailure(recSegmentNo, Pipeline.ErrorCode.DATA_HAS_NO_SEGMENT,
                       "Error decoding the name segment number " +
                       data.getName().get(-1).toEscapedString() + ": " + ex);
    return;
  }

  // set finalBlockId
  if (!this.hasFinalBlockId && data.getMetaInfo().getFinalBlockId().getValue().size() > 0) {
    try {
      this.finalBlockId = data.getMetaInfo().getFinalBlockId().toSegment();
    }
    catch (ex) {
      this.handleFailure(recSegmentNo, Pipeline.ErrorCode.DATA_HAS_NO_SEGMENT,
                         "Error decoding the name segment number " +
                         data.getName().get(-1).toEscapedString() + ": " + ex);
      return;
    }
    this.hasFinalBlockId = true;

    // Save the content
    this.contentParts[recSegmentNo] = data.getContent().buf();


    if (this.hasFailure && this.finalBlockId >= this.failedSegNo) {
      // previously failed segment is part of the content
      return this.onFailure(this.failureReason);
    }
    else {
      this.hasFailure = false;
    }
  }

  var recSeg = this.segmentInfo[recSegmentNo];
  if (recSeg === undefined) {
    return; // ignore already-received segment
  }

  var rtt = Date.now() - recSeg.timeSent;
  if (LOG > 1) {
    console.log ("Received segment #" + recSegmentNo
                 + ", rtt=" + rtt + "ms"
                 + ", rto=" + recSeg.rto + "ms");
  }

  if (this.highData < recSegmentNo) {
    this.highData = recSegmentNo;
  }

  // for segments in retx queue, we must not decrement nInFlight
  // because it was already decremented when the segment timed out
  if (recSeg.state !== PipelineCubic.SegmentState.InRetxQueue) {
    this.nInFlight--;
  }

  // do not sample RTT for retransmitted segments
  if ((recSeg.state === PipelineCubic.SegmentState.FirstTimeSent ||
       recSeg.state === PipelineCubic.SegmentState.InRetxQueue) &&
      this.retxCount[recSegmentNo] === undefined) {
    var nExpectedSamples = Math.max((this.nInFlight + 1) >> 1, 1);
    if (nExpectedSamples <= 0) {
      console.log("ERROR: nExpectedSamples is less than or equal to ZERO");
    }
    this.rttEstimator.addMeasurement(recSegmentNo, rtt, nExpectedSamples);
  }

  // clear the entry associated with the received segment
  this.segmentInfo[recSegmentNo] = undefined;  // do not splice

  this.numberOfSatisfiedSegments++;
  // Check whether we are finished
  if (this.hasFinalBlockId && this.numberOfSatisfiedSegments > this.finalBlockId) {
    // Concatenate to get content.
    var content = Buffer.concat(this.contentParts);
    this.cancelInFlightSegmentsGreaterThan(this.finalBlockId);
    try {
      this.cancel();
      this.printSummary();
      this.onComplete(new Blob(content, false));
    } catch (ex) {
      console.log("Error in onComplete: " + NdnCommon.getErrorWithStackTrace(ex));
    }
    return;
  }

  this.increaseWindow();

  // Fetch the next segments
  this.schedulePackets();
};

PipelineCubic.prototype.getNextSegmentNo = function()
{
  return this.nextSegmentNo++;
};

PipelineCubic.prototype.checkRto = function()
{
  if (this.isStopped)
    return;

  var hasTimeout = false;

  for (var i=0; i < this.segmentInfo.length; ++i) {
    if (this.segmentInfo[i] === undefined)
      continue;

    var segInfo = this.segmentInfo[i];
    if (segInfo.state !== PipelineCubic.SegmentState.InRetxQueue) { // skip segments already in the retx queue
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

  // schedule the next check after predefined interval
  setTimeout(this.checkRto.bind(this), this.rtoCheckInterval);
};

PipelineCubic.prototype.enqueueForRetransmission = function(segNo)
{
  if (this.nInFlight <= 0) {
    console.log("ERROR: number of in-flight segments is less than or equal to ZERO");
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
  for (var i=segNo + 1; i < this.segmentInfo.length; ++i) {
    // cancel fetching all segments that follow
    if (this.segmentInfo[i] !== undefined)
      this.face.removePendingInterest(this.segmentInfo[i].pendingInterestId);

    this.segmentInfo[i] = undefined;  // do no splice
    this.nInFlight--;
  }
};

PipelineCubic.prototype.handleFail = function(segNo, errCode, reason)
{
  if (this.isStopped)
    return;

  // if the failed segment is definitely part of the content, raise a fatal error
  if (segNo === 0 || (this.hasFinalBlockId && segNo <= this.finalBlockId))
    return this.onFailure(errCode, reason);

  if (!this.hasFinalBlockId) {
    this.segmentInfo[segNo] = undefined;  // do not splice
    this.nInFlight--;

    var empty = true;
    for (i=0; i < this.segmentInfo.length; ++i) {
      if (this.segmentInfo[i] !== undefined) {
        empty = false;
        break;
      }
    }

    if (empty) {
      this.onFailure(Pipeline.ErrorCode.NO_FINALBLOCK,
                     "Fetching terminated at segment " + segNo +
                     " but no finalBlockId has been found");
    }
    else {
      this.cancelInFlightSegmentsGreaterThan(segNo);
      this.hasFailure = true;
      this.failedSegNo = segNo;
      this.failureReason = reason;
    }
  }
};

PipelineCubic.prototype.handleLifetimeExpiration = function(interest)
{
  if (this.isStopped)
    return;

  this.nTimeouts++;
  var recSeg = 0; // the very first Interest does not have segment number
  // treated the same as timeout for now
  if (interest.getName().get(-1).isSegment())
    recSeg = interest.getName().get(-1).toSegment();

  this.enqueueForRetransmission(recSeg);

  this.onWarning(Pipeline.ErrorCode.INTEREST_LIFETIME_EXPIRATION,
                 "handle interest lifetime expiration for segment " + recSeg);

  this.recordTimeout();
  this.schedulePackets();
};

PipelineCubic.prototype.handleNack = function(interest)
{
  if (this.isStopped)
    return;

  var recSeg = 0; // the very first Interest does not have segment number
  // treated the same as timeout for now
  if (interest.getName().components.length > 0 && interest.getName().get(-1).isSegment())
    recSeg = interest.getName().get(-1).toSegment();

  this.enqueueForRetransmission(recSeg);

  this.onWarning(Pipeline.ErrorCode.NACK_RECEIVED, "handle nack for segment " + recSeg);

  this.recordTimeout();
  this.schedulePackets();
};

PipelineCubic.prototype.onValidationFailed = function(data, reason)
{
  Pipeline.reportError(this.onError, Pipeline.ErrorCode.SEGMENT_VERIFICATION_FAILED,
                       "Segment verification failed for " + data.getName().toUri() +
                       " . Reason: " + reason);
};

PipelineCubic.prototype.onFailure = function(errCode, reason)
{
  this.cancel();
  Pipeline.reportError(this.onError, errCode, reason);
};

PipelineCubic.prototype.onWarning = function(errCode, reason)
{
  if (LOG > 2) {
    Pipeline.reportWarning(errCode, reason);
  }
};

PipelineCubic.prototype.printSummary = function()
{
  if (LOG < 3)
    return;

  var statMsg = "";
  if (this.rttEstimator.getMinRtt() === Number.MAX_VALUE ||
      this.rttEstimator.getMaxRtt() === Number.NEGATIVE_INFINITY) {
     statMsg = "stats unavailable";
   }
   else {
     statMsg = "min/avg/max = " + this.rttEstimator.getMinRtt().toPrecision(3) + "/"
                                + this.rttEstimator.getAvgRtt().toPrecision(3) + "/"
                                + this.rttEstimator.getMaxRtt().toPrecision(3) + " ms";
  }

  console.log("Timeouts: " + this.nTimeouts + " (caused " + this.nLossDecr + " window decreases)\n" +
              "Retransmitted segments: " + this.nRetransmitted +
              " (" + (this.nSent == 0 ? 0 : (this.nRetransmitted / this.nSent * 100))  + "%)" +
              ", skipped: " + this.nSkippedRetx + "\n" +
              "RTT " + statMsg);

};
