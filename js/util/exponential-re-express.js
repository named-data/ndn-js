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
 * An ExponentialReExpress uses an internal onTimeout to express the interest again
 * with double the interestLifetime. See ExponentialReExpress.makeOnTimeout,
 * which you should call instead of the private constructor.
 * Create a new ExponentialReExpress where onTimeout expresses the interest
 * again with double the interestLifetime. If the interesLifetime goes
 * over settings.maxInterestLifetime, then call the given onTimeout. If this
 * internally gets onData, just call the given onData.
 * @constructor
 */
var ExponentialReExpress = function ExponentialReExpress
  (face, onData, onTimeout, settings)
{
  settings = (settings || {});
  this.face = face;
  this.callerOnData = onData;
  this.callerOnTimeout = onTimeout;

  this.maxInterestLifetime = (settings.maxInterestLifetime || 16000);
};

exports.ExponentialReExpress = ExponentialReExpress;

/**
 * Return a callback to use in expressInterest for onTimeout which will express
 * the interest again with double the interestLifetime. If the interesLifetime
 * goes over maxInterestLifetime (see settings below), then call the provided
 * onTimeout. If a Data packet is received, this calls the provided onData.
 * Use it like this:
 *   var onData = function() { ... };
 *   var onTimeout = function() { ... };
 *   face.expressInterest
 *     (interest, onData,
 *      ExponentialReExpress.makeOnTimeout(face, onData, onTimeout));
 * @param {Face} face This calls face.expressInterest.
 * @param {function} onData When a matching data packet is received, this calls
 * onData(interest, data) where interest is the interest given to
 * expressInterest and data is the received Data object. This is normally the
 * same onData you initially passed to expressInterest.
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onTimeout If the interesLifetime goes over
 * maxInterestLifetime, this calls onTimeout(interest). However, if onTimeout is
 * null, this does not use it.
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {Object} settings (optional) If not null, an associative array with
 * the following defaults:
 * {
 *   maxInterestLifetime: 16000 // milliseconds
 * }
 * @return {function} The onTimeout callback to pass to expressInterest.
 */
ExponentialReExpress.makeOnTimeout = function(face, onData, onTimeout, settings)
{
  var reExpress = new ExponentialReExpress(face, onData, onTimeout, settings);
  return function(interest) { reExpress.onTimeout(interest); };
};

ExponentialReExpress.prototype.onTimeout = function(interest)
{
  var interestLifetime = interest.getInterestLifetimeMilliseconds();
  if (interestLifetime == null) {
    // Can't re-express.
    if (this.callerOnTimeout) {
      try {
        this.callerOnTimeout(interest);
      } catch (ex) {
        console.log("Error in onTimeout: " + NdnCommon.getErrorWithStackTrace(ex));
      }
    }
    return;
  }

  var nextInterestLifetime = interestLifetime * 2;
  if (nextInterestLifetime > this.maxInterestLifetime) {
    if (this.callerOnTimeout) {
      try {
        this.callerOnTimeout(interest);
      } catch (ex) {
        console.log("Error in onTimeout: " + NdnCommon.getErrorWithStackTrace(ex));
      }
    }
    return;
  }

  var nextInterest = interest.clone();
  nextInterest.setInterestLifetimeMilliseconds(nextInterestLifetime);
  var thisObject = this;
  this.face.expressInterest
    (nextInterest, this.callerOnData,
     function(localInterest) { thisObject.onTimeout(localInterest); });
};
