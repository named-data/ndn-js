/**
 * Provide the callback closure for the async communication methods in the Face class.
 * Copyright (C) 2013-2015 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * This is a port of Closure.py from PyNDN, written by:
 * Derek Kulinski <takeda@takeda.tk>
 * Jeff Burke <jburke@ucla.edu>
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
 * A subclass of Closure is passed to expressInterest and registerPrefix.
 * @deprecated You should use the forms of expressInterest and registerPrefix which use callbacks instead of Closure.
 * @constructor
 */
var Closure = function Closure()
{
  // I don't think storing Face's closure is needed
  // and it creates a reference loop, as of now both
  // of those variables are never set -- Derek
  //
  // Use instance variables to return data to callback
  this.ndn_data = null;  // this holds the ndn_closure
  this.ndn_data_dirty = false;
};

exports.Closure = Closure;

// Upcall result
Closure.RESULT_ERR               = -1; // upcall detected an error
Closure.RESULT_OK                =  0; // normal upcall return
Closure.RESULT_REEXPRESS         =  1; // reexpress the same interest again
Closure.RESULT_INTEREST_CONSUMED =  2; // upcall claims to consume interest
Closure.RESULT_VERIFY            =  3; // force an unverified result to be verified
Closure.RESULT_FETCHKEY          =  4; // get the key in the key locator and re-call the interest
                                       //   with the key available in the local storage

// Upcall kind
Closure.UPCALL_FINAL              = 0; // handler is about to be deregistered
Closure.UPCALL_INTEREST           = 1; // incoming interest
Closure.UPCALL_CONSUMED_INTEREST  = 2; // incoming interest, someone has answered
Closure.UPCALL_CONTENT            = 3; // incoming verified content
Closure.UPCALL_INTEREST_TIMED_OUT = 4; // interest timed out
Closure.UPCALL_CONTENT_UNVERIFIED = 5; // content that has not been verified
Closure.UPCALL_CONTENT_BAD        = 6; // verification failed

/**
 * Override this in your subclass.
 * If you're getting strange errors in upcall()
 * check your code whether you're returning a value.
 */
Closure.prototype.upcall = function(kind, upcallInfo)
{
  //dump('upcall ' + this + " " + kind + " " + upcallInfo + "\n");
  return Closure.RESULT_OK;
};

/**
 * An UpcallInfo is passed to Closure.upcall.
 * @constructor
 */
var UpcallInfo = function UpcallInfo(face, interest, matchedComps, data)
{
  this.face = face;  // Face object (not used)
  this.ndn = face;   // deprecated
  this.interest = interest;  // Interest object
  this.matchedComps = matchedComps;  // int
  this.data = data;  // Data
  this.contentObject = data; // deprecated.  Include for backward compatibility.
};

UpcallInfo.prototype.toString = function()
{
  var ret = "face = " + this.face;
  ret += "\nInterest = " + this.interest;
  ret += "\nmatchedComps = " + this.matchedComps;
  ret += "\nData: " + this.data;
  return ret;
};

exports.UpcallInfo = UpcallInfo;
