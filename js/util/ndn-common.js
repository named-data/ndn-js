/**
 * Encapsulate a Buffer and support dynamic reallocation.
 * Copyright (C) 2015-2018 Regents of the University of California.
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
var printStackTrace = require('../../contrib/stacktrace/stacktrace.js').printStackTrace;

/**
 * NdnCommon has static NDN utility methods and constants.
 * @constructor
 */
var NdnCommon = {};

exports.NdnCommon = NdnCommon;

/**
 * The practical limit of the size of a network-layer packet. If a packet is
 * larger than this, the library or application MAY drop it. This constant is
 * defined in this low-level class so that internal code can use it, but
 * applications should use the static API method
 * Face.getMaxNdnPacketSize() which is equivalent.
 */
NdnCommon.MAX_NDN_PACKET_SIZE = 8800;

/**
 * Get the error message plus its stack trace.
 * @param {Error} error The error object.
 * @return {string} The error message, plus the stack trace with each line
 * separated by '\n'.
 */
NdnCommon.getErrorWithStackTrace = function(error)
{
  return error + '\n' + printStackTrace({e: error}).join('\n');
};

/**
 * Check for Indexed DB support and call onComplete with the result as described
 * below. This has to use an onComplete callback since IndexedDB is async.
 * @param {function} onComplete This calls onComplete(haveIndexedDb) where
 * haveIndexedDb is true if the browser has Indexed DB support, otherwise false.
 */
NdnCommon.checkIndexedDb = function(onComplete)
{
  try {
    var database = new Dexie("test-Dexie-support");
    database.version(1).stores({});
    database.open();

    // Give Dexie a little time to open.
    setTimeout(function() {
      try {
        onComplete(database.isOpen());
      } catch (ex) {
        onComplete(false);
      }
    }, 200);
  } catch (ex) {
    onComplete(false);
  }
};
