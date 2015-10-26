/**
 * Copyright (C) 2015 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt unit tests
 * https://github.com/named-data/ndn-group-encrypt/blob/master/tests/unit-tests/schedule.t.cpp
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version, with the additional exemption that
 * compiling, linking, and/or using OpenSSL is allowed.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var assert = require("assert");
var Blob = require('../../..').Blob;
var RepetitiveInterval = require('../../..').RepetitiveInterval;
var Schedule = require('../../..').Schedule;
var Common = require('./unit-tests-common.js').UnitTestsCommon;

var SCHEDULE = new Buffer([
  0x8f, 0xc4,// Schedule
  0x8d, 0x90,// WhiteIntervalList
  /////
  0x8c, 0x2e, // RepetitiveInterval
    0x86, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x35, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x87, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x35, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x88, 0x01,
      0x04,
    0x89, 0x01,
      0x07,
    0x8a, 0x01,
      0x00,
    0x8b, 0x01,
      0x00,
  /////
  0x8c, 0x2e, // RepetitiveInterval
    0x86, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x35, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x87, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x38, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x88, 0x01,
      0x05,
    0x89, 0x01,
      0x0a,
    0x8a, 0x01,
      0x02,
    0x8b, 0x01,
      0x01,
  /////
  0x8c, 0x2e, // RepetitiveInterval
    0x86, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x35, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x87, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x38, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x88, 0x01,
      0x06,
    0x89, 0x01,
      0x08,
    0x8a, 0x01,
      0x01,
    0x8b, 0x01,
      0x01,
  /////
  0x8e, 0x30, // BlackIntervalList
  /////
  0x8c, 0x2e, // RepetitiveInterval
     0x86, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x37, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x87, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x37, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x88, 0x01,
      0x07,
    0x89, 0x01,
      0x08,
    0x8a, 0x01,
      0x00,
    0x8b, 0x01,
      0x00
]);

describe('TestSchedule', function() {
  it('CalculateCoveringInterval', function() {
    var schedule = new Schedule();
    
    var interval1 = new RepetitiveInterval
      (Common.fromIsoString("20150825T000000"),
       Common.fromIsoString("20150827T000000"), 5, 10, 2,
       RepetitiveInterval.RepeatUnit.DAY);
    var interval2 = new RepetitiveInterval
      (Common.fromIsoString("20150825T000000"),
       Common.fromIsoString("20150827T000000"), 6, 8, 1,
       RepetitiveInterval.RepeatUnit.DAY);
    var interval3 = new RepetitiveInterval
      (Common.fromIsoString("20150827T000000"),
       Common.fromIsoString("20150827T000000"), 7, 8);
    var interval4 = new RepetitiveInterval
      (Common.fromIsoString("20150825T000000"),
       Common.fromIsoString("20150825T000000"), 4, 7);

    schedule.addWhiteInterval(interval1);
    schedule.addWhiteInterval(interval2);
    schedule.addWhiteInterval(interval4);
    schedule.addBlackInterval(interval3);

    var result;
    
    // timePoint1 --> positive 8.25 4-10
    var timePoint1 = Common.fromIsoString("20150825T063000");
    result = schedule.getCoveringInterval(timePoint1);
    assert.ok(true == result.isPositive);
    assert.ok("20150825T040000" == Common.toIsoString(result.interval.getStartTime()));
    assert.ok("20150825T100000" == Common.toIsoString(result.interval.getEndTime()));

    // timePoint2 --> positive 8.26 6-8
    var timePoint2 = Common.fromIsoString("20150826T073000");
    result = schedule.getCoveringInterval(timePoint2);
    assert.ok(true == result.isPositive);
    assert.ok("20150826T060000" == Common.toIsoString(result.interval.getStartTime()));
    assert.ok("20150826T080000" == Common.toIsoString(result.interval.getEndTime()));

    // timePoint3 --> positive 8.27 5-7
    var timePoint3 = Common.fromIsoString("20150827T053000");
    result = schedule.getCoveringInterval(timePoint3);
    assert.ok(true == result.isPositive);
    assert.ok("20150827T050000" == Common.toIsoString(result.interval.getStartTime()));
    assert.ok("20150827T070000" == Common.toIsoString(result.interval.getEndTime()));

    // timePoint4 --> positive 8.27 5-7
    var timePoint4 = Common.fromIsoString("20150827T063000");
    result = schedule.getCoveringInterval(timePoint4);
    assert.ok(true == result.isPositive);
    assert.ok("20150827T050000" == Common.toIsoString(result.interval.getStartTime()));
    assert.ok("20150827T070000" == Common.toIsoString(result.interval.getEndTime()));

    // timePoint5 --> negative 8.27 7-8
    var timePoint5 = Common.fromIsoString("20150827T073000");
    result = schedule.getCoveringInterval(timePoint5);
    assert.ok(false == result.isPositive);
    assert.ok(false == result.interval.isEmpty());
    assert.ok("20150827T070000" == Common.toIsoString(result.interval.getStartTime()));
    assert.ok("20150827T080000" == Common.toIsoString(result.interval.getEndTime()));

    // timePoint6 --> negative 8.25 10-24
    var timePoint6 = Common.fromIsoString("20150825T113000");
    result = schedule.getCoveringInterval(timePoint6);
    assert.ok(false == result.isPositive);
    assert.ok(false == result.interval.isEmpty());
    assert.ok("20150825T100000" == Common.toIsoString(result.interval.getStartTime()));
    assert.ok("20150826T000000" == Common.toIsoString(result.interval.getEndTime()));
  });

  it('EncodeAndDecode', function() {
    var schedule = new Schedule();

    var interval1 = new RepetitiveInterval
      (Common.fromIsoString("20150825T000000"),
       Common.fromIsoString("20150828T000000"), 5, 10, 2,
       RepetitiveInterval.RepeatUnit.DAY);
    var interval2 = new RepetitiveInterval
      (Common.fromIsoString("20150825T000000"),
       Common.fromIsoString("20150828T000000"), 6, 8, 1,
       RepetitiveInterval.RepeatUnit.DAY);
    var interval3 = new RepetitiveInterval
      (Common.fromIsoString("20150827T000000"),
       Common.fromIsoString("20150827T000000"), 7, 8);
    var interval4 = new RepetitiveInterval
      (Common.fromIsoString("20150825T000000"),
       Common.fromIsoString("20150825T000000"), 4, 7);

    schedule.addWhiteInterval(interval1);
    schedule.addWhiteInterval(interval2);
    schedule.addWhiteInterval(interval4);
    schedule.addBlackInterval(interval3);

    var encoding = schedule.wireEncode();
    var encoding2 = new Blob(SCHEDULE, false);
    assert.ok(encoding.equals(encoding2));

    var schedule2 = new Schedule();
    schedule2.wireDecode(encoding);
    var result;

    // timePoint1 --> positive 8.25 4-10
    var timePoint1 = Common.fromIsoString("20150825T063000");
    result = schedule.getCoveringInterval(timePoint1);
    assert.ok(true == result.isPositive);
    assert.ok("20150825T040000" == Common.toIsoString(result.interval.getStartTime()));
    assert.ok("20150825T100000" == Common.toIsoString(result.interval.getEndTime()));

    // timePoint2 --> positive 8.26 6-8
    var timePoint2 = Common.fromIsoString("20150826T073000");
    result = schedule.getCoveringInterval(timePoint2);
    assert.ok(true == result.isPositive);
    assert.ok("20150826T060000" == Common.toIsoString(result.interval.getStartTime()));
    assert.ok("20150826T080000" == Common.toIsoString(result.interval.getEndTime()));
  });
});
