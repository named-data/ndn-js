/**
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 * This is the closure class for use in expressInterest to re express with exponential falloff.
 */

var Closure = require('../closure.js').Closure;

/**
 * Create a new ExponentialReExpressClosure where upcall responds to UPCALL_INTEREST_TIMED_OUT
 *   by expressing the interest again with double the interestLifetime. If the interesLifetime goes
 *   over maxInterestLifetime, then call callerClosure.upcall with UPCALL_INTEREST_TIMED_OUT.
 * When upcall is not UPCALL_INTEREST_TIMED_OUT, just call callerClosure.upcall.
 * @constructor
 * @param {Closure} callerClosure
 * @param {Object} settings if not null, an associative array with the following defaults:
 * {
 *   maxInterestLifetime: 16000 // milliseconds
 * }
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
      var interestLifetime = upcallInfo.interest.interestLifetime;
      if (interestLifetime == null)
        return this.callerClosure.upcall(Closure.UPCALL_INTEREST_TIMED_OUT, upcallInfo);
            
      var nextInterestLifetime = interestLifetime * 2;
      if (nextInterestLifetime > this.maxInterestLifetime)
        return this.callerClosure.upcall(Closure.UPCALL_INTEREST_TIMED_OUT, upcallInfo);
            
      var nextInterest = upcallInfo.interest.clone();
      nextInterest.interestLifetime = nextInterestLifetime;
      // TODO: Use expressInterest with callbacks, not Closure.
      upcallInfo.face.expressInterest(nextInterest.name, this, nextInterest);
      return Closure.RESULT_OK;
    }  
    else
      return this.callerClosure.upcall(kind, upcallInfo);
  } catch (ex) {
    console.log("ExponentialReExpressClosure.upcall exception: " + ex);
    return Closure.RESULT_ERR;
  }
};
