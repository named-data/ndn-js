/**
 * Encapsulate a Buffer and support dynamic reallocation.
 * Copyright (C) 2015 Regents of the University of California.
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
 * Use apply to call a function and then use a continuation function to process
 * the result synchronously or asynchronously as follows. If doAsync, then
 * append continuation to the argument list when calling apply, so that the
 * continuation processes the result asynchronously. Otherwise, immediately call
 * continuation with the value and return the result synchronously. This is
 * needed for functions which allow an optional onComplete callback for
 * asynchronous mode. For example, you can call:
 * function myOptionalAsyncFunc(x, y, onComplete) {
 *   // Do some stuff to create someObject.
 *   return applyThen(someObject, "someMethod", [x, y], onComplete, function(val) {
 *     // Process val and create the result.
 *     return complete(onComplete, result);
 *   });
 * }
 *
 * If onComplete is omitted, then the effective synchronous code is:
 * function myOptionalAsyncFunc(x, y, onComplete) {
 *   // Do some stuff to create someObject.
 *   var val = someObject.someMethod(x, y);
 *   // Process val and create the result.
 *   return result;
 * }
 *
 * If onComplete is supplied, then the effective asynchronous code is:
 * function myOptionalAsyncFunc(x, y, onComplete) {
 *   // Do some stuff to create someObject.
 *   someObject.someMethod(x, y, function(val) {
 *     // Process val and create the result.
 *     onComplete(result);
 *   });
 * }
 *
 * @param {object} thisArg The "this" value for calling apply.
 * @param {function|string} func The function for calling apply. If func is a
 * string, then the function is thisArg[func]. The function's last argument must
 * be an optional onComplete callback for asynchronoous mode.
 * @param {array} args The array of arguments for calling apply. If doAsync, then
 * continuation is appended to args.
 * @param {boolean} doAsync If doAsync, then append continuation to args for
 * calling apply. Otheriwse, pass the result of apply to continuation and return
 * the result. As shown in the example above, you should simply pass onComplete
 * so that doAsync is true if onComplete is supplied. But note that applyThen
 * does not use onComplete itself - instead onComplete is used by the
 * continuation function.
 * @param {function} continuation A function which takes the result from calling
 * apply, and continues processing.
 * @return {any} If !doAsync, this returns the result of calling
 * continuation. Otherwise this returns undefined.
 */
NdnCommon.applyThen = function(thisArg, func, args, doAsync, continuation)
{
  if (typeof func === 'string')
    func = thisArg[func];

  if (doAsync)
    // Pass control to the callback.
    func.apply(thisArg, args.concat([continuation]));
  else
    return continuation(func.apply(thisArg, args));
}

/**
 * If onComplete is omitted, just return the  value synchronously. Otherwise
 * call onComplete(value) to provide it asynchronously. This is needed for
 * functions which allow an optional onComplete callback for asynchronous mode.
 * The function should finish with: return complete(onComplete, value);
 * @param {function} onComplete (optional) If supplied, this calls
 * onComplete(value).
 * @param {any} value The value for onComplete(value), or to return if onComplete
 * is omitted.
 * @return {any} If onComplete is omitted, this returns value. Otherwise this
 * returns undefined.
 */
NdnCommon.complete = function(onComplete, value)
{
  if (onComplete)
    onComplete(value);
  else
    return value;
}
