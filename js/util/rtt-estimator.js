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
var Pipeline = require('./pipeline.js').Pipeline;

/**
 * Round Trip Time Estimator
 *
 * This class implements the "Mean-Deviation" RTT estimator, as discussed in RFC 6298,
 * with the modifications to RTO calculation described in RFC 7323 Appendix G.
 *
 * @param {Object} opts An object that can contain RTT estimator options to overwrite their default
 *                 values. If null is passed then all options will be set to their default values.
 */
var RttEstimator = function RttEstimator(opts)
{
  // Options
  this.alpha = Pipeline.op("alpha", 0.125, opts); // parameter for RTT estimation
  this.beta = Pipeline.op("beta", 0.25, opts); // parameter for RTT variation calculation
  this.k = Pipeline.op("k", 8, opts); // factor of RTT variation when calculating RTO
  this.initialRto = Pipeline.op("initialRto", 1000, opts); // initial RTO value (ms)
  this.minRto = Pipeline.op("minRto", 200, opts); // lower bound of RTO (ms)
  this.maxRto = Pipeline.op("maxRto", 20000, opts); // upper bound of RTO (ms)
  this.rtoBackoffMultiplier = Pipeline.op("rtoBackoffMultiplier", 2, opts);

  this.delayArr = [];  // keep track of full delay of each segment to calculate ave jitter

  this.sRtt = NaN; // smoothed RTT
  this.rttVar = NaN; // RTT variation
  this.rto = this.initialRto;
  this.rttMin = Number.MAX_VALUE;
  this.rttMax = Number.NEGATIVE_INFINITY;
  this.rttAvg = 0;
  this.nRttSamples = 0;
}

exports.RttEstimator = RttEstimator;

RttEstimator.prototype.clamp = function(v, min, max)
{
  if (min < v && v < max) {
    return v
  } else if (v < min) {
    return min
  } else if (max < v) {
    return max
  }
};

/**
 * Add a new RTT measurement to the estimator for the given received segment.
 *
 * @param segNo the segment number of the received segmented Data
 * @param rtt the sampled rtt
 * @param nExpectedSamples number of expected samples, must be greater than 0.
 *        It should be set to current number of in-flight Interests. Please
 *        refer to Appendix G of RFC 7323 for details.
 *
 * NOTE: Don't take RTT measurement for retransmitted segments
 */
RttEstimator.prototype.addMeasurement = function(segNo, rtt, nExpectedSamples)
{
  if (nExpectedSamples <= 0) {
    console.log("ERROR: nExpectedSamples is less than or equal to ZERO");
  }

  if (this.nRttSamples === 0) { // first measurement
    this.sRtt = rtt;
    this.rttVar = this.sRtt / 2;
    this.rto = this.sRtt + this.k * this.rttVar;
  }
  else {
    var alpha = this.alpha / nExpectedSamples;
    var beta = this.beta / nExpectedSamples;
    this.rttVar = (1 - beta) * this.rttVar + beta * Math.abs(this.sRtt - rtt);
    this.sRtt = (1 - alpha) * this.sRtt + alpha * rtt;
    this.rto = this.sRtt + this.k * this.rttVar;
  }

  this.rto = this.clamp(this.rto, this.minRto, this.maxRto);

  this.rttAvg = (this.nRttSamples * this.rttAvg + rtt) / (this.nRttSamples + 1);
  this.rttMax = Math.max(rtt, this.rttMax);
  this.rttMin = Math.min(rtt, this.rttMin);

  this.nRttSamples++;
};

RttEstimator.prototype.addDelayMeasurement = function(segNo, delay)
{
  this.delayArr[segNo] = delay;
};

/**
 * Return average of retrieved segments' RTT variance
 */
RttEstimator.prototype.getAvgJitter = function()
{
  var samples = 0;
  var jitterAvg = 0;
  var jitterLast = 0;
  for (var i = 0; i < this.delayArr.length; ++i) {
    if (this.delayArr[i] === undefined)
      continue;
    if (samples > 0) {
      jitterAvg = ((jitterAvg * samples) + Math.abs(jitterLast - this.delayArr[i])) / (samples + 1);
    }
    jitterLast = this.delayArr[i];
    samples++;
  }
  return jitterAvg;
};

RttEstimator.prototype.backoffRto = function()
{
  this.rto = this.clamp(this.rto * this.rtobackoffmultiplier, this.minrto, this.maxrto);
};

RttEstimator.prototype.getEstimatedRto = function()
{
  return this.rto;
};

RttEstimator.prototype.getMinRtt = function()
{
  return this.rttMin;
};

RttEstimator.prototype.getMaxRtt = function()
{
  return this.rttMax;
};

RttEstimator.prototype.getAvgRtt = function()
{
  return this.rttAvg;
};
