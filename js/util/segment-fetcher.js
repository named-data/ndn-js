/**
 * Copyright (C) 2015-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: Chavoosh Ghasemi <chghasemi@cs.arizona.edu>
 * @author: From ndn-cxx util/segment-fetcher https://github.com/named-data/ndn-cxx
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
var KeyChain = require('../security/key-chain.js').KeyChain; /** @ignore */
var NdnCommon = require('./ndn-common.js').NdnCommon;
var PipelineFixed = require('./pipeline-fixed.js').PipelineFixed;

var SegmentFetcher = function SegmentFetcher() { };

exports.SegmentFetcher = SegmentFetcher;

/**
 * An ErrorCode value is passed in the onError callback.
 */
SegmentFetcher.ErrorCode = {
  INTEREST_TIMEOUT: 1,
  DATA_HAS_NO_SEGMENT: 2,
  SEGMENT_VERIFICATION_FAILED: 3
};


/**
 * DontVerifySegment may be used in fetch to skip validation of Data packets.
 */
SegmentFetcher.DontVerifySegment = function(data)
{
  return true;
};

/**
 * SegmentFetcher is a utility class to fetch segmented data with the latest
 * version by using a pipeline.
 *
 * The available pipelines are:
 * - Pipeline Fixed [default]
 * - [TODO] Pipeline Aimd
 *
 * Initiate segment fetching.
 *
 * There are two forms of fetch:
 * fetch(face, baseInterest, validatorKeyChain, onComplete, onError)
 * and
 * fetch(face, baseInterest, verifySegment, onComplete, onError)
 * @param {Face} face This face is used by pipeline to express Interests and fetch segments.
 * @param {Interest} baseInterest An Interest for the initial segment of the
 * requested data, where baseInterest.getName() has the name prefix. This
 * interest may include a custom InterestLifetime and selectors that will
 * propagate to all subsequent Interests. The only exception is that the initial
 * Interest will be forced to include selector "MustBeFresh=true" which will
 * be turned off in subsequent Interests.
 * @param validatorKeyChain {KeyChain} This is used by ValidatorKeyChain.verifyData(data).
 * If validation fails then abort fetching and call onError with SEGMENT_VERIFICATION_FAILED.
 * This does not make a copy of the KeyChain; the object must remain valid while fetching.
 * If validatorKeyChain is null, this does not validate the data packet.
 * @param {function} verifySegment This is used by verifySegment(data) method in pipeline
 * class when a Data packet is received. If it returns false then abort fetching and call
 * onError with ErrorCode.SEGMENT_VERIFICATION_FAILED. If data validation is
 * not required, use SegmentFetcher.DontVerifySegment.
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
 *
 * Example:
 *     var onComplete = function(content) { ... }
 *
 *     var onError = function(errorCode, message) { ... }
 *
 *     var interest = new Interest(new Name("/data/prefix"));
 *     interest.setInterestLifetimeMilliseconds(1000);
 *     SegmentFetcher.fetch(face, interest, null, onComplete, onError);
 */
SegmentFetcher.fetch = function
  (face, baseInterest, validatorKeyChainOrVerifySegment, onComplete, onError)
{
  var basePrefix = baseInterest.getName().toUri();

  if (validatorKeyChainOrVerifySegment == null ||
      validatorKeyChainOrVerifySegment instanceof KeyChain)
    new PipelineFixed
      (basePrefix, face, validatorKeyChainOrVerifySegment,
       onComplete, onError)
      .fetchFirstSegment(baseInterest);
  else
    new PipelineFixed
      (basePrefix, face, null, onComplete, onError)
      .fetchFirstSegment(baseInterest);
};
