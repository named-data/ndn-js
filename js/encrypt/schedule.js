/**
 * Copyright (C) 2015-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt src/schedule https://github.com/named-data/ndn-group-encrypt
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
var Interval = require('./interval.js').Interval; /** @ignore */
var RepetitiveInterval = require('./repetitive-interval.js').RepetitiveInterval; /** @ignore */
var Tlv = require('../encoding/tlv/tlv.js').Tlv; /** @ignore */
var TlvEncoder = require('../encoding/tlv/tlv-encoder.js').TlvEncoder; /** @ignore */
var TlvDecoder = require('../encoding/tlv/tlv-decoder.js').TlvDecoder; /** @ignore */
var Blob = require('../util/blob.js').Blob;

/**
 * Schedule is used to manage the times when a member can access data using two
 * sets of RepetitiveInterval as follows. whiteIntervalList is an ordered
 * set for the times a member is allowed to access to data, and
 * blackIntervalList is for the times a member is not allowed.
 * Create a Schedule with one of these forms:
 * Schedule() A Schedule with empty whiteIntervalList and blackIntervalList.
 * Schedule(schedule). A copy of the given schedule.
 * @note This class is an experimental feature. The API may change.
 * @constructor
 */
var Schedule = function Schedule(value)
{
  if (typeof value === 'object' && value instanceof Schedule) {
    // Make a copy.
    var schedule = value;

    // RepetitiveInterval is immutable, so we don't need to make a deep copy.
    this.whiteIntervalList_ = schedule.whiteIntervalList_.slice(0);
    this.blackIntervalList_ = schedule.blackIntervalList_.slice(0);
  }
  else {
    // The default constructor.
    this.whiteIntervalList_ = [];
    this.blackIntervalList_ = [];
  }
};

exports.Schedule = Schedule;

/**
 * Add the repetitiveInterval to the whiteIntervalList.
 * @param {RepetitiveInterval} repetitiveInterval The RepetitiveInterval to add.
 * If the list already contains the same RepetitiveInterval, this does nothing.
 * @return {Schedule} This Schedule so you can chain calls to add.
 */
Schedule.prototype.addWhiteInterval = function(repetitiveInterval)
{
  // RepetitiveInterval is immutable, so we don't need to make a copy.
  Schedule.sortedSetAdd_(this.whiteIntervalList_, repetitiveInterval);
  return this;
};

/**
 * Add the repetitiveInterval to the blackIntervalList.
 * @param {RepetitiveInterval} repetitiveInterval The RepetitiveInterval to add.
 * If the list already contains the same RepetitiveInterval, this does nothing.
 * @return {Schedule} This Schedule so you can chain calls to add.
 */
Schedule.prototype.addBlackInterval = function(repetitiveInterval)
{
  // RepetitiveInterval is immutable, so we don't need to make a copy.
  Schedule.sortedSetAdd_(this.blackIntervalList_, repetitiveInterval);
  return this;
};

/**
 * Get the interval that covers the time stamp. This iterates over the two
 * repetitive interval sets and find the shortest interval that allows a group
 * member to access the data. If there is no interval covering the time stamp,
 * this returns false for isPositive and a negative interval.
 * @param {number} timeStamp The time stamp as milliseconds since Jan 1, 1970 UTC.
 * @return {object} An associative array with fields
 * (isPositive, interval) where
 * isPositive is true if the returned interval is positive or false if negative,
 * and interval is the Interval covering the time stamp, or a negative interval
 * if not found.
 */
Schedule.prototype.getCoveringInterval = function(timeStamp)
{
  var blackPositiveResult = new Interval(true);
  var whitePositiveResult = new Interval(true);

  var blackNegativeResult = new Interval();
  var whiteNegativeResult = new Interval();

  // Get the black result.
  Schedule.calculateIntervalResult_
    (this.blackIntervalList_, timeStamp, blackPositiveResult, blackNegativeResult);

  // If the black positive result is not empty, then isPositive must be false.
  if (!blackPositiveResult.isEmpty())
    return { isPositive: false, interval: blackPositiveResult };

  // Get the whiteResult.
  Schedule.calculateIntervalResult_
    (this.whiteIntervalList_, timeStamp, whitePositiveResult, whiteNegativeResult);

  if (whitePositiveResult.isEmpty() && !whiteNegativeResult.isValid()) {
    // There is no white interval covering the time stamp.
    // Return false and a 24-hour interval.
    var timeStampDateOnly =
      RepetitiveInterval.toDateOnlyMilliseconds_(timeStamp);
    return { isPositive: false,
             interval:  new Interval
               (timeStampDateOnly,
                timeStampDateOnly + RepetitiveInterval.MILLISECONDS_IN_DAY) };
  }

  if (!whitePositiveResult.isEmpty()) {
    // There is white interval covering the time stamp.
    // Return true and calculate the intersection.
    if (blackNegativeResult.isValid())
      return { isPositive: true,
               interval: whitePositiveResult.intersectWith(blackNegativeResult) };
    else
      return  { isPositive: true, interval: whitePositiveResult };
  }
  else
    // There is no white interval covering the time stamp.
    // Return false.
    return { isPositive: false, interval: whiteNegativeResult };
};

/**
 * Encode this Schedule.
 * @return {Blob} The encoded buffer.
 */
Schedule.prototype.wireEncode = function()
{
  // For now, don't use WireFormat and hardcode to use TLV since the encoding
  // doesn't go out over the wire, only into the local SQL database.
  var encoder = new TlvEncoder(256);
  var saveLength = encoder.getLength();

  // Encode backwards.
  // Encode the blackIntervalList.
  var saveLengthForList = encoder.getLength();
  for (var i = this.blackIntervalList_.length - 1; i >= 0; i--)
    Schedule.encodeRepetitiveInterval_(this.blackIntervalList_[i], encoder);
  encoder.writeTypeAndLength
    (Tlv.Encrypt_BlackIntervalList, encoder.getLength() - saveLengthForList);

  // Encode the whiteIntervalList.
  saveLengthForList = encoder.getLength();
  for (var i = this.whiteIntervalList_.length - 1; i >= 0; i--)
    Schedule.encodeRepetitiveInterval_(this.whiteIntervalList_[i], encoder);
  encoder.writeTypeAndLength
    (Tlv.Encrypt_WhiteIntervalList, encoder.getLength() - saveLengthForList);

  encoder.writeTypeAndLength
    (Tlv.Encrypt_Schedule, encoder.getLength() - saveLength);

  return new Blob(encoder.getOutput(), false);
};

/**
 * Decode the input and update this Schedule object.
 * @param {Blob|Buffer} input The input buffer to decode. For Buffer, this reads
 * from position() to limit(), but does not change the position.
 * @throws DecodingException For invalid encoding.
 */
Schedule.prototype.wireDecode = function(input)
{
  // If input is a blob, get its buf().
  var decodeBuffer = typeof input === 'object' && input instanceof Blob ?
    input.buf() : input;

  // For now, don't use WireFormat and hardcode to use TLV since the encoding
  // doesn't go out over the wire, only into the local SQL database.
  var decoder = new TlvDecoder(decodeBuffer);

  var endOffset = decoder.readNestedTlvsStart(Tlv.Encrypt_Schedule);

  // Decode the whiteIntervalList.
  this.whiteIntervalList_ = [];
  var listEndOffset = decoder.readNestedTlvsStart(Tlv.Encrypt_WhiteIntervalList);
  while (decoder.getOffset() < listEndOffset)
    Schedule.sortedSetAdd_
      (this.whiteIntervalList_, Schedule.decodeRepetitiveInterval_(decoder));
  decoder.finishNestedTlvs(listEndOffset);

  // Decode the blackIntervalList.
  this.blackIntervalList_ = [];
  listEndOffset = decoder.readNestedTlvsStart(Tlv.Encrypt_BlackIntervalList);
  while (decoder.getOffset() < listEndOffset)
    Schedule.sortedSetAdd_
      (this.blackIntervalList_, Schedule.decodeRepetitiveInterval_(decoder));
  decoder.finishNestedTlvs(listEndOffset);

  decoder.finishNestedTlvs(endOffset);
};

/**
 * Insert element into the list, sorted using element.compare(). If it is a
 * duplicate of an existing list element, don't add it.
 */
Schedule.sortedSetAdd_ = function(list, element)
{
  // Find the index of the first element where it is not less than element.
  var i = 0;
  while (i < list.length) {
    var comparison = list[i].compare(element);
    if (comparison == 0)
      // Don't add a duplicate.
      return;
    if (!(comparison < 0))
      break;

    ++i;
  }

  list.splice(i, 0, element);
};

/**
 * Encode the RepetitiveInterval as NDN-TLV to the encoder.
 * @param {RepetitiveInterval} repetitiveInterval The RepetitiveInterval to encode.
 * @param {TlvEncoder} encoder The TlvEncoder to receive the encoding.
 */
Schedule.encodeRepetitiveInterval_ = function(repetitiveInterval, encoder)
{
  var saveLength = encoder.getLength();

  // Encode backwards.
  // The RepeatUnit enum has the same values as the encoding.
  encoder.writeNonNegativeIntegerTlv
    (Tlv.Encrypt_RepeatUnit, repetitiveInterval.getRepeatUnit());
  encoder.writeNonNegativeIntegerTlv
    (Tlv.Encrypt_NRepeats, repetitiveInterval.getNRepeats());
  encoder.writeNonNegativeIntegerTlv
    (Tlv.Encrypt_IntervalEndHour, repetitiveInterval.getIntervalEndHour());
  encoder.writeNonNegativeIntegerTlv
    (Tlv.Encrypt_IntervalStartHour, repetitiveInterval.getIntervalStartHour());
  // Use Blob to convert the string to UTF8 encoding.
  encoder.writeBlobTlv(Tlv.Encrypt_EndDate,
    new Blob(Schedule.toIsoString(repetitiveInterval.getEndDate())).buf());
  encoder.writeBlobTlv(Tlv.Encrypt_StartDate,
    new Blob(Schedule.toIsoString(repetitiveInterval.getStartDate())).buf());

  encoder.writeTypeAndLength
    (Tlv.Encrypt_RepetitiveInterval, encoder.getLength() - saveLength);
};

/**
 * Decode the input as an NDN-TLV RepetitiveInterval.
 * @param {TlvDecoder} decoder The decoder with the input to decode.
 * @return {RepetitiveInterval} A new RepetitiveInterval with the decoded result.
 */
Schedule.decodeRepetitiveInterval_ = function(decoder)
{
  var endOffset = decoder.readNestedTlvsStart(Tlv.Encrypt_RepetitiveInterval);

  // Use Blob to convert UTF8 to a string.
  var startDate = Schedule.fromIsoString
    (new Blob(decoder.readBlobTlv(Tlv.Encrypt_StartDate), true).toString());
  var endDate = Schedule.fromIsoString
    (new Blob(decoder.readBlobTlv(Tlv.Encrypt_EndDate), true).toString());
  var startHour = decoder.readNonNegativeIntegerTlv(Tlv.Encrypt_IntervalStartHour);
  var endHour = decoder.readNonNegativeIntegerTlv(Tlv.Encrypt_IntervalEndHour);
  var nRepeats = decoder.readNonNegativeIntegerTlv(Tlv.Encrypt_NRepeats);

  // The RepeatUnit enum has the same values as the encoding.
  var repeatUnit = decoder.readNonNegativeIntegerTlv(Tlv.Encrypt_RepeatUnit);

  decoder.finishNestedTlvs(endOffset);
  return new RepetitiveInterval
    (startDate, endDate, startHour, endHour, nRepeats, repeatUnit);
};

/**
 * A helper function to calculate black interval results or white interval
 * results.
 * @param {Array} list The set of RepetitiveInterval, which can be the white
 * list or the black list.
 * @param {number} timeStamp The time stamp as milliseconds since Jan 1, 1970 UTC.
 * @param {Interval} positiveResult The positive result which is updated.
 * @param {Interval} negativeResult The negative result which is updated.
 */
Schedule.calculateIntervalResult_ = function
  (list, timeStamp, positiveResult, negativeResult)
{
  for (var i = 0; i < list.length; ++i) {
    var element = list[i];

    var result = element.getInterval(timeStamp);
    var tempInterval = result.interval;
    if (result.isPositive == true)
      positiveResult.unionWith(tempInterval);
    else {
      if (!negativeResult.isValid())
        negativeResult.set(tempInterval);
      else
        negativeResult.intersectWith(tempInterval);
    }
  }
};

/**
 * Convert a UNIX timestamp to ISO time representation with the "T" in the middle.
 * @param {number} msSince1970 Timestamp as milliseconds since Jan 1, 1970 UTC.
 * @return {string} The string representation.
 */
Schedule.toIsoString = function(msSince1970)
{
  var utcTime = new Date(Math.round(msSince1970));
  return utcTime.getUTCFullYear() +
         Schedule.to2DigitString(utcTime.getUTCMonth() + 1) +
         Schedule.to2DigitString(utcTime.getUTCDate()) +
         "T" +
         Schedule.to2DigitString(utcTime.getUTCHours()) +
         Schedule.to2DigitString(utcTime.getUTCMinutes()) +
         Schedule.to2DigitString(utcTime.getUTCSeconds());
};

/**
 * A private method to zero pad an integer to 2 digits.
 * @param {number} x The number to pad.  Assume it is a non-negative integer.
 * @return {string} The padded string.
 */
Schedule.to2DigitString = function(x)
{
  var result = x.toString();
  return result.length === 1 ? "0" + result : result;
};

/**
 * Convert an ISO time representation with the "T" in the middle to a UNIX
 * timestamp.
 * @param {string} timeString The ISO time representation.
 * @return {number} The timestamp as milliseconds since Jan 1, 1970 UTC.
 */
Schedule.fromIsoString = function(timeString)
{
  if (timeString.length != 15 || timeString.substr(8, 1) != 'T')
    throw new Error("fromIsoString: Format is not the expected yyyymmddThhmmss");

  return Date.UTC
    (parseInt(timeString.substr(0, 4)),
     parseInt(timeString.substr(4, 2) - 1),
     parseInt(timeString.substr(6, 2)),
     parseInt(timeString.substr(9, 2)),
     parseInt(timeString.substr(11, 2)),
     parseInt(timeString.substr(13, 2)));
};
