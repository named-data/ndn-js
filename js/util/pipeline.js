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

var NdnCommon = require('./ndn-common.js').NdnCommon;

/**
 * Here are some basic assumptions and logics that are applied to all pipelines in the library:
 *
 * The data is named /<prefix>/<version>/<segment>, where:
 * - <prefix> is the specified name prefix,
 * - <version> is an unknown version that needs to be discovered, and
 * - <segment> is a segment number.
 *
 * Note: The number of segments is unknown and is controlled by
 *       `FinalBlockId` field in one of the retrieved Data packet.
 *       This field should exist at least in the last Data packet.
 *
 * The following logic is implemented in all pipelines:
 *
 * 1. Express the first Interest to discover the version:
 *
 *    >> Interest: /<prefix>?MustBeFresh=true
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
 *
 * In order to validate individual segments, a KeyChain needs to be supplied to a given pipeline.
 * If verifyData fails, the fetching process is aborted with SEGMENT_VERIFICATION_FAILED.
 * If data validation is not required, pass null.
 */
var Pipeline = function Pipeline () { }

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
  MAX_NACK_TIMEOUT_RETRIES: 8
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

exports.Pipeline = Pipeline;
