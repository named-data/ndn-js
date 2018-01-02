/**
 * Copyright (C) 2015-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt src/repetitive-interval https://github.com/named-data/ndn-group-encrypt
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
var Interval = require('./interval.js').Interval;

/**
 * A RepetitiveInterval is an advanced interval which can repeat and can be used
 * to find a simple Interval that a time point falls in. Create a
 * RepetitiveInterval with one of these forms:
 * RepetitiveInterval() A RepetitiveInterval with one day duration, non-repeating..
 * RepetitiveInterval(startDate, endDate, intervalStartHour, intervalEndHour, nRepeats, repeatUnit).
 * RepetitiveInterval(repetitiveInterval).
 * @param {number} startDate The start date as milliseconds since Jan 1, 1970 UTC.
 * startDate must be earlier than or same as endDate. Or if repeatUnit is
 * RepetitiveInterval.RepeatUnit.NONE, then it must equal endDate.
 * @param {number} endDate The end date as milliseconds since Jan 1, 1970 UTC.
 * @param {number} intervalStartHour The start hour in the day, from 0 to 23.
 * intervalStartHour must be less than intervalEndHour.
 * @param {number} intervalEndHour The end hour in the day from 1 to 24.
 * @param {number} nRepeats (optional) Repeat the interval nRepeats repetitions,
 * every unit, until endDate. If ommitted, use 0.
 * @param {number} repeatUnit (optional) The unit of the repetition, from
 * RepetitiveInterval.RepeatUnit. If ommitted, use NONE. If this is NONE or
 * ommitted, then startDate must equal endDate.
 * @note This class is an experimental feature. The API may change.
 * @constructor
 */
var RepetitiveInterval = function RepetitiveInterval
  (startDate, endDate, intervalStartHour, intervalEndHour, nRepeats, repeatUnit)
{
  if (typeof startDate === 'object' && startDate instanceof RepetitiveInterval) {
    // Make a copy.
    repetitiveInterval = startDate;

    this.startDate_ = repetitiveInterval.startDate_;
    this.endDate_ = repetitiveInterval.endDate_;
    this.intervalStartHour_ = repetitiveInterval.intervalStartHour_;
    this.intervalEndHour_ = repetitiveInterval.intervalEndHour_;
    this.nRepeats_ = repetitiveInterval.nRepeats_;
    this.repeatUnit_ = repetitiveInterval.repeatUnit_;
  }
  else if (typeof startDate === 'number') {
    if (nRepeats == undefined)
      nRepeats = 0;
    if (repeatUnit == undefined)
      repeatUnit = RepetitiveInterval.RepeatUnit.NONE;

    this.startDate_ = RepetitiveInterval.toDateOnlyMilliseconds_(startDate);
    this.endDate_ = RepetitiveInterval.toDateOnlyMilliseconds_(endDate);
    this.intervalStartHour_ = Math.round(intervalStartHour);
    this.intervalEndHour_ = Math.round(intervalEndHour);
    this.nRepeats_ = Math.round(nRepeats);
    this.repeatUnit_ = repeatUnit;

    // Validate.
    if (!(this.intervalStartHour_ < this.intervalEndHour_))
      throw new Error("ReptitiveInterval: startHour must be less than endHour");
    if (!(this.startDate_ <= this.endDate_))
      throw new Error
        ("ReptitiveInterval: startDate must be earlier than or same as endDate");
    if (!(this.intervalStartHour_ >= 0))
      throw new Error("ReptitiveInterval: intervalStartHour must be non-negative");
    if (!(this.intervalEndHour_ >= 1 && this.intervalEndHour_ <= 24))
      throw new Error("ReptitiveInterval: intervalEndHour must be from 1 to 24");
    if (this.repeatUnit_ == RepetitiveInterval.RepeatUnit.NONE) {
      if (!(this.startDate_ == this.endDate_))
        throw new Error
          ("ReptitiveInterval: With RepeatUnit.NONE, startDate must equal endDate");
    }
  }
  else {
    // The default constructor.
    this.startDate_ = -Number.MAX_VALUE;
    this.endDate_ = -Number.MAX_VALUE;
    this.intervalStartHour_ = 0;
    this.intervalEndHour_ = 24;
    this.nRepeats_ = 0;
    this.repeatUnit_ = RepetitiveInterval.RepeatUnit.NONE;
  }
};

exports.RepetitiveInterval = RepetitiveInterval;

RepetitiveInterval.RepeatUnit = {
  NONE:  0,
  DAY:   1,
  MONTH: 2,
  YEAR:  3
};

/**
 * Get an interval that covers the time point. If there is no interval
 * covering the time point, this returns false for isPositive and returns a
 * negative interval.
 * @param {number} timePoint The time point as milliseconds since Jan 1, 1970 UTC.
 * @return {object} An associative array with fields
 * (isPositive, interval) where
 * isPositive is true if the returned interval is
 * positive or false if negative, and interval is the Interval covering the time
 * point or a negative interval if not found.
 */
RepetitiveInterval.prototype.getInterval = function(timePoint)
{
  var isPositive;
  var startTime;
  var endTime;

  if (!this.hasIntervalOnDate_(timePoint)) {
    // There is no interval on the date of timePoint.
    startTime = RepetitiveInterval.toDateOnlyMilliseconds_(timePoint);
    endTime = RepetitiveInterval.toDateOnlyMilliseconds_(timePoint) +
      24 * RepetitiveInterval.MILLISECONDS_IN_HOUR;
    isPositive = false;
  }
  else {
    // There is an interval on the date of timePoint.
    startTime = RepetitiveInterval.toDateOnlyMilliseconds_(timePoint) +
      this.intervalStartHour_ * RepetitiveInterval.MILLISECONDS_IN_HOUR;
    endTime = RepetitiveInterval.toDateOnlyMilliseconds_(timePoint) +
      this.intervalEndHour_ * RepetitiveInterval.MILLISECONDS_IN_HOUR;

    // check if in the time duration
    if (timePoint < startTime) {
      endTime = startTime;
      startTime = RepetitiveInterval.toDateOnlyMilliseconds_(timePoint);
      isPositive = false;
    }
    else if (timePoint > endTime) {
      startTime = endTime;
      endTime = RepetitiveInterval.toDateOnlyMilliseconds_(timePoint) +
        RepetitiveInterval.MILLISECONDS_IN_DAY;
      isPositive = false;
    }
    else
      isPositive = true;
  }

  return { isPositive: isPositive, interval: new Interval(startTime, endTime) };
};

/**
 * Compare this to the other RepetitiveInterval.
 * @param {RepetitiveInterval} other The other RepetitiveInterval to compare to.
 * @return {number} -1 if this is less than the other, 1 if greater and 0 if equal.
 */
RepetitiveInterval.prototype.compare = function(other)
{
  if (this.startDate_ < other.startDate_)
    return -1;
  if (this.startDate_ > other.startDate_)
    return 1;

  if (this.endDate_ < other.endDate_)
    return -1;
  if (this.endDate_ > other.endDate_)
    return 1;

  if (this.intervalStartHour_ < other.intervalStartHour_)
    return -1;
  if (this.intervalStartHour_ > other.intervalStartHour_)
    return 1;

  if (this.intervalEndHour_ < other.intervalEndHour_)
    return -1;
  if (this.intervalEndHour_ > other.intervalEndHour_)
    return 1;

  if (this.nRepeats_ < other.nRepeats_)
    return -1;
  if (this.nRepeats_ > other.nRepeats_)
    return 1;

  if (this.repeatUnit_ < other.repeatUnit_)
    return -1;
  if (this.repeatUnit_ > other.repeatUnit_)
    return 1;

  return 0;
};

/**
 * Get the start date.
 * @return {number} The start date as milliseconds since Jan 1, 1970 UTC.
 */
RepetitiveInterval.prototype.getStartDate = function()
{
  return this.startDate_;
};

/**
 * Get the end date.
 * @return {number} The end date as milliseconds since Jan 1, 1970 UTC.
 */
RepetitiveInterval.prototype.getEndDate = function()
{
  return this.endDate_;
};

/**
 * Get the interval start hour.
 * @return {number} The interval start hour.
 */
RepetitiveInterval.prototype.getIntervalStartHour = function()
{
  return this.intervalStartHour_;
}

/**
 * Get the interval end hour.
 * @return {number} The interval end hour.
 */
RepetitiveInterval.prototype.getIntervalEndHour = function()
{
  return this.intervalEndHour_;
};

/**
 * Get the number of repeats.
 * @return {number} The number of repeats.
 */
RepetitiveInterval.prototype.getNRepeats = function()
{
  return this.nRepeats_;
};

/**
 * Get the repeat unit.
 * @return {number} The repeat unit, from RepetitiveInterval.RepeatUnit.
 */
RepetitiveInterval.prototype.getRepeatUnit = function()
{
  return this.repeatUnit_;
};

/**
 * Check if the date of the time point is in any interval.
 * @param {number} timePoint The time point as milliseconds since Jan 1, 1970 UTC.
 * @return {boolean} True if the date of the time point is in any interval.
 */
RepetitiveInterval.prototype.hasIntervalOnDate_ = function(timePoint)
{
  var timePointDateMilliseconds = RepetitiveInterval.toDateOnlyMilliseconds_(timePoint);

  if (timePointDateMilliseconds < this.startDate_ ||
      timePointDateMilliseconds > this.endDate_)
    return false;

  if (this.repeatUnit_ == RepetitiveInterval.RepeatUnit.NONE)
    return true;
  else if (this.repeatUnit_ == RepetitiveInterval.RepeatUnit.DAY) {
    var durationDays = (timePointDateMilliseconds - this.startDate_) /
                        RepetitiveInterval.MILLISECONDS_IN_DAY;
    if (durationDays % this.nRepeats_ == 0)
      return true;
  }
  else {
    var timePointDate = new Date(timePointDateMilliseconds);
    var startDate = new Date(this.startDate_);

    if (this.repeatUnit_ == RepetitiveInterval.RepeatUnit.MONTH &&
             timePointDate.getUTCDate() == startDate.getUTCDate()) {
      var yearDifference =
        timePointDate.getUTCFullYear() - startDate.getUTCFullYear();
      var monthDifference = 12 * yearDifference +
        timePointDate.getUTCMonth() - startDate.getUTCMonth();
      if (monthDifference % this.nRepeats_ == 0)
        return true;
    }
    else if (this.repeatUnit_ == RepetitiveInterval.RepeatUnit.YEAR &&
             timePointDate.getUTCDate() == startDate.getUTCDate() &&
             timePointDate.getUTCMonth() == startDate.getUTCMonth()) {
      var difference = timePointDate.getUTCFullYear() - startDate.getUTCFullYear();
      if (difference % this.nRepeats_ == 0)
        return true;
    }
  }

  return false;
};

/**
 * Return a time point on the beginning of the date (without hours, minutes, etc.)
 * @param {number} timePoint The time point as milliseconds since Jan 1, 1970 UTC.
 * @return {number} A time point as milliseconds since Jan 1, 1970 UTC.
 */
RepetitiveInterval.toDateOnlyMilliseconds_ = function(timePoint)
{
  var result = Math.round(timePoint);
  result -= result % RepetitiveInterval.MILLISECONDS_IN_DAY;
  return result;
};

RepetitiveInterval.MILLISECONDS_IN_HOUR = 3600 * 1000;
RepetitiveInterval.MILLISECONDS_IN_DAY = 24 * 3600 * 1000;
