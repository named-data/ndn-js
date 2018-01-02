/**
 * Copyright (C) 2015-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt src/interval https://github.com/named-data/ndn-group-encrypt
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
 * An Interval defines a time duration which contains a start timestamp and an
 * end timestamp. Create an Interval with one of these forms:
 * Interval(isValid).
 * Interval(startTime, endTime).
 * Interval(interval).
 * @param {boolean} isValid True to create a valid empty interval, false to
 * create an invalid interval.
 * @param {number} startTime The start time as milliseconds since Jan 1, 1970 UTC.
 * The start time must be less than the end time. To create an empty interval
 * (start time equals end time), use the constructor Interval(true).
 * @param {number} endTime The end time as milliseconds since Jan 1, 1970 UTC.
 * @param {Interval} interval The other interval with values to copy.
 * @note This class is an experimental feature. The API may change.
 * @constructor
 */
var Interval = function Interval(value, endTime)
{
  if (typeof value === 'object' && value instanceof Interval) {
    // Make a copy.
    this.startTime_ = value.startTime_;
    this.endTime_ = value.endTime_;
    this.isValid_ = value.isValid_;
  }
  else if (typeof value === 'number') {
    var startTime = value;

    if (!(startTime < endTime))
      throw new Error("Interval start time must be less than the end time");

    this.startTime_ = startTime;
    this.endTime_ = endTime;
    this.isValid_ = true;
  }
  else {
    var isValid = (value ? true : false);

    this.startTime_ = -Number.MAX_VALUE;
    this.endTime_ = -Number.MAX_VALUE;
    this.isValid_ = isValid;
  }
};

exports.Interval = Interval;

/**
 * Set this interval to have the same values as the other interval.
 * @param {Interval} other The other Interval with values to copy.
 */
Interval.prototype.set = function(other)
{
  this.startTime_ = other.startTime_;
  this.endTime_ = other.endTime_;
  this.isValid_ = other.isValid_;
};

/**
 * Check if the time point is in this interval.
 * @param {number} timePoint The time point to check as milliseconds since
 * Jan 1, 1970 UTC.
 * @return {boolean} True if timePoint is in this interval.
 * @throws Error if this Interval is invalid.
 */
Interval.prototype.covers = function(timePoint)
{
  if (!this.isValid_)
    throw new Error("Interval.covers: This Interval is invalid");

  if (this.isEmpty())
    return false;
  else
    return this.startTime_ <= timePoint && timePoint < this.endTime_;
};

/**
 * Set this Interval to the intersection of this and the other interval.
 * This and the other interval should be valid but either can be empty.
 * @param {Interval} interval The other Interval to intersect with.
 * @return {Interval} This Interval.
 * @throws Error if this Interval or the other interval is invalid.
 */
Interval.prototype.intersectWith = function(interval)
{
  if (!this.isValid_)
    throw new Error("Interval.intersectWith: This Interval is invalid");
  if (!interval.isValid_)
    throw new Error("Interval.intersectWith: The other Interval is invalid");

  if (this.isEmpty() || interval.isEmpty()) {
    // If either is empty, the result is empty.
    this.startTime_ = this.endTime_;
    return this;
  }

  if (this.startTime_ >= interval.endTime_ || this.endTime_ <= interval.startTime_) {
    // The two intervals don't have an intersection, so the result is empty.
    this.startTime_ = this.endTime_;
    return this;
  }

  // Get the start time.
  if (this.startTime_ <= interval.startTime_)
    this.startTime_ = interval.startTime_;

  // Get the end time.
  if (this.endTime_ > interval.endTime_)
    this.endTime_ = interval.endTime_;

  return this;
};

/**
 * Set this Interval to the union of this and the other interval.
 * This and the other interval should be valid but either can be empty.
 * This and the other interval should have an intersection. (Contiguous
 * intervals are not allowed.)
 * @param {Interval} interval The other Interval to union with.
 * @return {Interval} This Interval.
 * @throws Error if this Interval or the other interval is invalid, or if the
 * two intervals do not have an intersection.
 */
Interval.prototype.unionWith = function(interval)
{
  if (!this.isValid_)
    throw new Error("Interval.intersectWith: This Interval is invalid");
  if (!interval.isValid_)
    throw new Error("Interval.intersectWith: The other Interval is invalid");

  if (this.isEmpty()) {
    // This interval is empty, so use the other.
    this.startTime_ = interval.startTime_;
    this.endTime_ = interval.endTime_;
    return this;
  }

  if (interval.isEmpty())
    // The other interval is empty, so keep using this one.
    return this;

  if (this.startTime_ >= interval.endTime_ || this.endTime_ <= interval.startTime_)
    throw new Error
      ("Interval.unionWith: The two intervals do not have an intersection");

  // Get the start time.
  if (this.startTime_ > interval.startTime_)
    this.startTime_ = interval.startTime_;

  // Get the end time.
  if (this.endTime_ < interval.endTime_)
    this.endTime_ = interval.endTime_;

  return this;
};

/**
 * Get the start time.
 * @return {number} The start time as milliseconds since Jan 1, 1970 UTC.
 * @throws Error if this Interval is invalid.
 */
Interval.prototype.getStartTime = function()
{
  if (!this.isValid_)
    throw new Error("Interval.getStartTime: This Interval is invalid");
  return this.startTime_;
};

/**
 * Get the end time.
 * @return {number} The end time as milliseconds since Jan 1, 1970 UTC.
 * @throws Error if this Interval is invalid.
 */
Interval.prototype.getEndTime = function()
{
  if (!this.isValid_)
    throw new Error("Interval.getEndTime: This Interval is invalid");
  return this.endTime_;
};

/**
 * Check if this Interval is valid.
 * @return {boolean} True if this interval is valid, false if invalid.
 */
Interval.prototype.isValid = function() { return this.isValid_; };

/**
 * Check if this Interval is empty.
 * @return {boolean} True if this Interval is empty (start time equals end time),
 * false if not.
 * @throws Error if this Interval is invalid.
 */
Interval.prototype.isEmpty = function()
{
  if (!this.isValid_)
    throw new Error("Interval.isEmpty: This Interval is invalid");
  return this.startTime_ == this.endTime_;
};
