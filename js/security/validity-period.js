/**
 * Copyright (C) 2016-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx src/security https://github.com/named-data/ndn-cxx
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
 * A ValidityPeriod is used in a Data packet's SignatureInfo and represents the
 * begin and end times of a certificate's validity period.
 *
 * There are three forms of the ValidityPeriod constructor:
 * ValidityPeriod() - Create a default ValidityPeriod where the period is not
 * specified.
 * ValidityPeriod(validityPeriod) - Create a new ValidityPeriod with a copy of
 * the fields in the given validityPeriod object.
 * ValidityPeriod(notBefore, notAfter) - Create a ValidityPeriod with the given
 * period.
 * @param {ValidityPeriod} validityPeriod The ValidityPeriod to copy.
 * @param {number} notBefore The beginning of the validity period range as
 * milliseconds since Jan 1, 1970 UTC. Note that this is rounded up to the
 * nearest whole second.
 * @param {number} notAfter The end of the validity period range as milliseconds
 * since Jan 1, 1970 UTC. Note that this is rounded down to the nearest whole
 * second.
 * @constructor
 */
var ValidityPeriod = function ValidityPeriod(validityPeriodOrNotBefore, notAfter)
{
  this.changeCount_ = 0;

  if (typeof validityPeriodOrNotBefore === 'object' &&
      validityPeriodOrNotBefore instanceof ValidityPeriod) {
    // Copy values.
    validityPeriod = validityPeriodOrNotBefore;
    this.notBefore_ = validityPeriod.notBefore_;
    this.notAfter_ = validityPeriod.notAfter_;
  }
  else if (notAfter != undefined) {
    notBefore = validityPeriodOrNotBefore;
    this.setPeriod(notBefore, notAfter)
  }
  else
    this.clear();
};

exports.ValidityPeriod = ValidityPeriod;

/**
 * Check if the period has been set.
 * @return {boolean} True if the period has been set, false if the period is not
 * specified (after calling the default constructor or clear).
 */
ValidityPeriod.prototype.hasPeriod = function()
{
  return !(this.notBefore_ === Number.MAX_VALUE &&
           this.notAfter_ === -Number.MAX_VALUE);
};

/**
 * Get the beginning of the validity period range.
 * @return {number} The time as milliseconds since Jan 1, 1970 UTC.
 */
ValidityPeriod.prototype.getNotBefore = function() { return this.notBefore_; };

/**
 * Get the end of the validity period range.
 * @return {number} The time as milliseconds since Jan 1, 1970 UTC.
 */
ValidityPeriod.prototype.getNotAfter = function() { return this.notAfter_; };

/** Reset to a default ValidityPeriod where the period is not specified.
 */
ValidityPeriod.prototype.clear = function()
{
  this.notBefore_ = Number.MAX_VALUE;
  this.notAfter_ = -Number.MAX_VALUE;
  ++this.changeCount_;
};

/**
 * Set the validity period.
 * @param {number} notBefore The beginning of the validity period range as
 * milliseconds since Jan 1, 1970 UTC. Note that this is rounded up to the
 * nearest whole second.
 * @param {number} notAfter The end of the validity period range as milliseconds
 * since Jan 1, 1970 UTC. Note that this is rounded down to the nearest whole
 * second.
 * @return {ValidityPeriod} This ValidityPeriod so that you can chain calls to
 * update values.
 */
ValidityPeriod.prototype.setPeriod = function(notBefore, notAfter)
{
  // Round up to the nearest second.
  this.notBefore_ = Math.round(Math.ceil(Math.round(notBefore) / 1000.0) * 1000.0);
  // Round down to the nearest second.
  this.notAfter_ = Math.round(Math.floor(Math.round(notAfter) / 1000.0) * 1000.0);
  ++this.changeCount_;

  return this;
};

/**
 * Check if the time falls within the validity period.
 * @param {number} time (optional) The time to check as milliseconds since
 * Jan 1, 1970 UTC. If omitted, use the current time.
 * @return {boolean} True if the beginning of the validity period is less than
 * or equal to time and time is less than or equal to the end of the validity
 * period.
 */
ValidityPeriod.prototype.isValid = function(time)
{
  if (time == undefined)
      // Round up to the nearest second like in setPeriod.
      time = Math.round(Math.ceil
        (Math.round(new Date().getTime()) / 1000.0) * 1000.0);

  return this.notBefore_ <= time && time <= this.notAfter_;
};

/**
 * If the signature is a type that has a ValidityPeriod (so that
 * getFromSignature will succeed), return true. Note: This is a static method of
 * ValidityPeriod instead of a method of Signature so that the Signature base
 * class does not need to be overloaded with all the different kinds of
 * information that various signature algorithms may use.
 * @param {Signature} An object of a subclass of Signature.
 * @return {boolean} True if the signature is a type that has a ValidityPeriod,
 * otherwise false.
 */
ValidityPeriod.canGetFromSignature = function(signature)
{
  return signature.constructor != undefined &&
    (signature.constructor.name === "Sha256WithRsaSignature" ||
     signature.constructor.name === "Sha256WithEcdsaSignature");
};

/**
 * If the signature is a type that has a ValidityPeriod, then return it.
 * Otherwise throw an error.
 * @param {Signature} An object of a subclass of Signature.
 * @return {ValidityPeriod} The signature's ValidityPeriod. It is an error if
 * signature doesn't have a ValidityPeriod.
 */
ValidityPeriod.getFromSignature = function(signature)
{
  if (signature.constructor != undefined &&
      (signature.constructor.name === "Sha256WithRsaSignature" ||
       signature.constructor.name === "Sha256WithEcdsaSignature"))
    return signature.getValidityPeriod();
  else
    throw new Error
      ("ValidityPeriod.getFromSignature: Signature type does not have a ValidityPeriod");
};

/**
 * Get the change count, which is incremented each time this object is changed.
 * @return {number} The change count.
 */
ValidityPeriod.prototype.getChangeCount = function()
{
  return this.changeCount_;
};
