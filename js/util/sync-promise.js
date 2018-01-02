/**
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
var NdnCommon = require('./ndn-common.js').NdnCommon;

/**
 * A SyncPromise is a promise which is immediately fulfilled or rejected, used
 * to return a promise in synchronous code.
 * This private constructor creates a SyncPromise fulfilled or rejected with the
 * given value. You should normally not call this constructor but call
 * SyncPromise.resolve or SyncPromise.reject. Note that we don't need a
 * constructor like SyncPromise(function(resolve, reject)) because this would be
 * for scheduling the function to be called later, which we don't do.
 * @param {any} value If isRejected is false, this is the value of the fulfilled
 * promise, else if isRejected is true, this is the error.
 * @param {boolean} isRejected True to create a promise in the rejected state,
 * where value is the error.
 * @constructor
 */
var SyncPromise = function SyncPromise(value, isRejected)
{
  this.value = value;
  this.isRejected = isRejected;
};

exports.SyncPromise = SyncPromise;

/**
 * If this promise is fulfilled, immediately call onFulfilled with the fulfilled
 * value as described below. Otherwise, if this promise is rejected, immediately
 * call onRejected with the error as described below.
 * @param {function} (optional) onFulfilled If this promise is fulfilled, this
 * calls onFulfilled(value) with the value of this promise and returns the
 * result. The function should return a promise. To use all synchronous code,
 * onFulfilled should return SyncPromise.resolve(newValue).
 * @param {function} (optional) onRejected If this promise is rejected, this
 * calls onRejected(err) with the error value of this promise and returns the
 * result. The function should return a promise. To use all synchronous code,
 * onFulfilled should return SyncPromise.resolve(newValue) (or throw an
 * exception).
 * @return {Promise|SyncPromise} If this promise is fulfilled, return the result
 * of calling onFulfilled(value). Note that this does not create a promise which
 * is scheduled to execute later. Rather it immediately calls onFulfilled which
 * should return a promise. But if onFulfilled is undefined, simply return this
 * promise to pass it forward. If this promise is rejected, return the result of
 * calling onRejected(err) with the error value. But if onRejected is undefined,
 * simply return this promise to pass it forward. However, if onFulfilled or
 * onRejected throws an exception, then return a new SyncPromise in the rejected
 * state with the exception.
 */
SyncPromise.prototype.then = function(onFulfilled, onRejected)
{
  if (this.isRejected) {
    if (onRejected) {
      try {
        return onRejected(this.value);
      }
      catch(err) {
        return new SyncPromise(err, true);
      }
    }
    else
      // Pass the error forward.
      return this;
  }
  else {
    if (onFulfilled) {
      try {
        return onFulfilled(this.value);
      }
      catch(err) {
        return new SyncPromise(err, true);
      }
    }
    else
      // Pass the fulfilled value forward.
      return this;
  }
};

/**
 * Call this.then(undefined, onRejected) and return the result. If this promise
 * is rejected then onRejected will process it. If this promise is fulfilled,
 * this simply passes it forward.
 */
SyncPromise.prototype.catch = function(onRejected)
{
  return this.then(undefined, onRejected);
};

/**
 * Return a new SyncPromise which is already fulfilled to the given value.
 * @param {any} value The value of the promise.
 */
SyncPromise.resolve = function(value)
{
  return new SyncPromise(value, false);
};

/**
 * Return a new SyncPromise which is already rejected with the given error.
 * @param {any} err The error for the rejected promise.
 */
SyncPromise.reject = function(err)
{
  return new SyncPromise(err, true);
};

/**
 * This static method checks if the promise is a SyncPromise and immediately
 * returns its value or throws the error if promise is rejected. If promise is
 * not a SyncPromise, this throws an exception since it is not possible to
 * immediately get the value. This can be used with "promise-based" code which
 * you expect to always return a SyncPromise to operate in synchronous mode.
 * @param {SyncPromise} promise The SyncPromise with the value to get.
 * @return {any} The value of the promise.
 * @throws Error If promise is not a SyncPromise.
 * @throws any If promise is a SyncPromise in the rejected state, this throws
 * the error.
 */
SyncPromise.getValue = function(promise)
{
  if (promise instanceof SyncPromise) {
    if (promise.isRejected)
      throw promise.value;
    else
      return promise.value;
  }
  else
    throw new Error("Cannot return immediately because promise is not a SyncPromise");
};

/**
 * This can be called with complete(onComplete, promise) or
 * complete(onComplete, onError, promise) to handle both synchronous and
 * asynchronous code based on whether the caller supplies the onComlete callback.
 * If onComplete is defined, call promise.then with a function which calls
 * onComplete(value) when fulfilled (possibly in asynchronous mode). If
 * onComplete is undefined, then we are in synchronous mode so return
 * SyncPromise.getValue(promise) which will throw an exception if the promise is
 * not a SyncPromise (or is a SyncPromise in the rejected state).
 * @param {function} onComplete If defined, this calls promise.then to fulfill
 * the promise, then calls onComplete(value) with the value of the promise.
 * If onComplete is undefined, the return value is described below.
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an error when this calls promise.then, this calls
 * onError(err) with the value of the error. If onComplete is undefined, then
 * onError is ignored and this will call SyncPromise.getValue(promise) which may
 * throw an exception.
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {Promise|SyncPromise} promise If onComplete is defined, this calls
 * promise.then. Otherwise, this calls SyncPromise.getValue(promise).
 * @return {any} If onComplete is undefined, return SyncPromise.getValue(promise).
 * Otherwise, if onComplete is supplied then return undefined and use
 * onComplete as described above.
 * @throws Error If onComplete is undefined and promise is not a SyncPromise.
 * @throws any If onComplete is undefined and promise is a SyncPromise in the
 * rejected state.
 */
SyncPromise.complete = function(onComplete, onErrorOrPromise, promise)
{
  var onError;
  if (promise)
    onError = onErrorOrPromise;
  else {
    promise = onErrorOrPromise;
    onError = null;
  }

  if (onComplete)
    promise
    .then(function(value) {
      try {
        onComplete(value);
      } catch (ex) {
        console.log("Error in onComplete: " + NdnCommon.getErrorWithStackTrace(ex));
      }
    }, function(err) {
      if (onError) {
        try {
          onError(err);
        } catch (ex) {
          console.log("Error in onError: " + NdnCommon.getErrorWithStackTrace(ex));
        }
      }
      else {
        if (promise instanceof SyncPromise)
          throw err;
        else
          // We are in an async promise callback, so a thrown exception won't
          // reach the caller. Just log it.
          console.log("Uncaught exception from a Promise: " +
            NdnCommon.getErrorWithStackTrace(err));
      }
    });
  else
    return SyncPromise.getValue(promise);
};
