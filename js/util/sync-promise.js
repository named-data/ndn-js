/**
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
 * A SyncPromise is a promise which is immediately fulfilled, used to return a
 * promise in synchronous code.
 * This private constructor creates a SyncPromise fulfilled with the given value.
 * You should normally not call this constructor but call SyncPromise.resolve.
 * Note that we don't need a constructor like
 * SyncPromise(function(resolve, reject)) because this is for scheduling the
 * function to be called later, which we don't do.
 * @param {any} value The value of the promise.
 * @constructor
 */
var SyncPromise = function SyncPromise(value)
{
  this.value = value;
};

exports.SyncPromise = SyncPromise;

/**
 * Immediately call onFulfilled with the value of this promise. 
 * @param {function} onFulfilled This calls onFulfilled(value) with the value of
 * this promise. The function should return a promise. To use all synchronous
 * code, onFulfilled should return SyncPromise.resolve(newValue).
 * @return {Promise|SyncPromise} The result of calling onFulfilled(value) which
 * should be a promise. Note that this does not create a promise which is
 * scheduled to execute later. Rather it immediately calls onFulfilled which
 * should return a promise.
 */
SyncPromise.prototype.then = function(onFulfilled)
{
  return onFulfilled(this.value);
};

/**
 * Return a new SyncPromise which is already fulfilled to the given value.
 * @param {any} value The value of the promise.
 */
SyncPromise.resolve = function(value)
{
  return new SyncPromise(value);
};

/**
 * This static method checks if the promise is a SyncPromise and immediately
 * returns its value. If it is not a SyncPromise, this throws an exceptions
 * since it is not possible to immediately get the value. This can be used with
 * "promise-based" code which you expect to always return a SyncPromise to
 * operate in synchronous mode.
 * @param {SyncPromise} promise The SyncPromise with the value to get.
 * @return {any} The value of the promise.
 * @throws {Error} If promise is not a SyncPromise.
 */
SyncPromise.getValue = function(promise)
{
  if (promise instanceof SyncPromise)
    return promise.value;
  else
    throw new Error("Cannot return immediately because promise is not a SyncPromise");
};

/**
 * If onComplete is defined, call promise.then with a function which calls
 * onComplete(value) when fulfilled (possibly in asynchronous mode). If
 * onComplete is undefined, then we are in synchronous mode so return
 * SyncPromise.getValue(promise) which will throw an exception if the promise is
 * not a SyncPromise. This static method can be used to handle both
 * synchronous and asynchronous code based on whether the caller supplies the
 * onComlete callback.
 * @param {function} onComplete If defined, this calls promise.then to fulfill
 * the promise, then calls onComplete(value) with the value of the promise.
 * If onComplete is undefined, the return value is described below.
 * @return {any} If onComplete is undefined, return SyncPromise.getValue(promise).
 * Otherwise, if onComplete is supplied then return undefined and use
 * onComplete as described above.
 * @throws {Error} If onComplete is undefined and promise is not a SyncPromise.
 */
SyncPromise.complete = function(onComplete, promise)
{
  if (onComplete)
    promise.then(function(value) { onComplete(value); });
  else
    return SyncPromise.getValue(promise);
};
