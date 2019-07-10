/**
 * Copyright (C) 2015-2019 Regents of the University of California.
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
var PipelineFixed = require('./pipeline-fixed.js').PipelineFixed; /** @ignore */
var PipelineCubic = require('./pipeline-cubic.js').PipelineCubic;

var SegmentFetcher = function SegmentFetcher() { };

exports.SegmentFetcher = SegmentFetcher;

/**
 * An ErrorCode value is passed in the onError callback.
 */
SegmentFetcher.ErrorCode = {
  INTEREST_TIMEOUT: 1,
  DATA_HAS_NO_SEGMENT: 2,
  SEGMENT_VERIFICATION_FAILED: 3,
  INVALID_KEYCHAIN: 4,
  INVALID_PIPELINE: 5
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
 * - Pipeline Fixed
 * - Pipeline Cubic [default]
 *
 * @param {Face} face This face is used by pipeline to express Interests and fetch segments.
 * @param {Interest} baseInterest An Interest for the initial segment of the requested data,
 *                                where baseInterest.getName() has the name prefix. This
 *                                interest may include a custom InterestLifetime that will
 *                                propagate to all subsequent Interests. The only exception
 *                                is that the initial Interest will be forced to include
 *                                "MustBeFresh=true" which will be turned off in subsequent Interests.
 * @param {KeyChain} validatorKeyChain This is used by ValidatorKeyChain.verifyData(data).
 *                                     If validation fails then abort fetching and call onError with
 *                                     SEGMENT_VERIFICATION_FAILED. This does not make a copy of the
 *                                     KeyChain; the object must remain valid while fetching. If
 *                                     validatorKeyChain is null, this does not validate the data packet.
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onComplete When all segments are received, call onComplete(content) where content is
 *                              a Blob which has the concatenation of the content of all the segments.
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onError Call onError.onError(errorCode, message) for listed error above, where errorCode
 *                           is a value from PipelineFixed.ErrorCode and message is a related string.
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {Object} opts (optional) An object that allows callers to choose one of the pipelines (i.e., `fixed` or `cubic`).
 *                                 It also can override the default values of the the chosen pipeline's parameters.
 *                                 If ommited or null, `cubic` pipeline will be used with its default values.
 * Examples:
 *     // Asking for `fixed` pipeline and overriding a couple of its parameters
 *     opts = {pipeline                  : "fixed",
 *             windowSize                : 20,
 *             maxRetriesOnTimeoutOrNack : 10}
 *
 *     // Asking for `cubic` pipeline and overriding one of its parameters
 *     opts = {pipeline   : "cubic",
 *             disableCwa : true}
 *
 *     // Asking for `cubic` pipeline (i.e., default pipeline) and overriding one of its parameters
 *     opts = {maxRetriesOnTimeoutOrNack : 10}
 *
 * @param {Object} stats (optional) An object that exposes statistics of pipeline's content retrieval performance
 *                                  to the caller.
 *                                  The caller should pass an empty object as `stats` - the content of this object
 *                                  will be overrided by the pipeline. Pipelines populate this object with the statistical
 *                                  information about the content retrieval. The caller can read object after the content
 *                                  retrieval process is done (probably in onComplete function).
 *                                  If omitted or null, the caller will not be able to access the stats.
 * NOTE: If the caller wants to use @param stats, it MUST specify @param opts (e.g., by passing null).
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
  (face, baseInterest, validatorKeyChain, onComplete, onError, opts, stats)
{
  if (opts == null || opts.pipeline === undefined || opts.pipeline === "cubic") {
    if (validatorKeyChain == null || validatorKeyChain instanceof KeyChain)
      new PipelineCubic
        (baseInterest, face, opts, validatorKeyChain, onComplete, onError, stats)
        .run();
    else
      onError(SegmentFetcher.ErrorCode.INVALID_KEYCHAIN,
              "validatorKeyChain should be either a KeyChain instance or null.");
  }
  else if (opts.pipeline === "fixed") {
    if (validatorKeyChain == null || validatorKeyChain instanceof KeyChain)
      new PipelineFixed
        (baseInterest, face, opts, validatorKeyChain, onComplete, onError, stats)
        .run();
    else
      onError(SegmentFetcher.ErrorCode.INVALID_KEYCHAIN,
              "validatorKeyChain should be either a KeyChain instance or null.");
  }
  else {
      onError(SegmentFetcher.ErrorCode.INVALID_PIPELINE,
              opts.pipeline + " is not a valid pipeline type");
  }
};
