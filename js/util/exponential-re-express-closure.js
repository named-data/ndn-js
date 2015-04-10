/**
 * This is the closure class for use in expressInterest to re express with exponential falloff.
 * Copyright (C) 2013-2015 Regents of the University of California.
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

var Closure = require('../closure.js').Closure;

/**
 * @deprecated Use ExponentialReExpress.makeOnTimeout().
 */
var ExponentialReExpressClosure = function ExponentialReExpressClosure(callerClosure, settings)
{
  // Inherit from Closure.
  Closure.call(this);

  this.callerClosure = callerClosure;
  settings = (settings || {});
  this.maxInterestLifetime = (settings.maxInterestLifetime || 16000);
};

exports.ExponentialReExpressClosure = ExponentialReExpressClosure;

/**
 * Wrap this.callerClosure to responds to UPCALL_INTEREST_TIMED_OUT
 *   by expressing the interest again as described in the constructor.
 */
ExponentialReExpressClosure.prototype.upcall = function(kind, upcallInfo)
{
  try {
    if (kind == Closure.UPCALL_INTEREST_TIMED_OUT) {
      var interestLifetime = upcallInfo.interest.getInterestLifetimeMilliseconds();
      if (interestLifetime == null)
        return this.callerClosure.upcall(Closure.UPCALL_INTEREST_TIMED_OUT, upcallInfo);

      var nextInterestLifetime = interestLifetime * 2;
      if (nextInterestLifetime > this.maxInterestLifetime)
        return this.callerClosure.upcall(Closure.UPCALL_INTEREST_TIMED_OUT, upcallInfo);

      var nextInterest = upcallInfo.interest.clone();
      nextInterest.setInterestLifetimeMilliseconds(nextInterestLifetime);
      // TODO: Use expressInterest with callbacks, not Closure.
      upcallInfo.face.expressInterest(nextInterest.getName(), this, nextInterest);
      return Closure.RESULT_OK;
    }
    else
      return this.callerClosure.upcall(kind, upcallInfo);
  } catch (ex) {
    console.log("ExponentialReExpressClosure.upcall exception: " + ex);
    return Closure.RESULT_ERR;
  }
};
