/**
 * Copyright (C) 2015 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt unit tests
 * https://github.com/named-data/ndn-group-encrypt/blob/master/tests/unit-tests/repetitive-interval.t.cpp
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
var RepetitiveInterval = require('../../..').RepetitiveInterval;
var Common = require('./unit-tests-common.js').UnitTestsCommon;

describe('TestRepetitiveInterval', function() {
  it('Construction', function() {
    var repetitiveInterval1 = new RepetitiveInterval
      (Common.fromIsoString("20150825T000000"),
       Common.fromIsoString("20150825T000000"), 5, 10);
    assert.ok("20150825T000000" == Common.toIsoString(repetitiveInterval1.getStartDate()));
    assert.ok("20150825T000000" == Common.toIsoString(repetitiveInterval1.getEndDate()));
    assert.ok(5 == repetitiveInterval1.getIntervalStartHour());
    assert.ok(10 == repetitiveInterval1.getIntervalEndHour());

    var repetitiveInterval2 = new RepetitiveInterval
      (Common.fromIsoString("20150825T000000"),
       Common.fromIsoString("20150827T000000"), 5, 10, 1,
       RepetitiveInterval.RepeatUnit.DAY);

    assert.ok(1 == repetitiveInterval2.getNRepeats());
    assert.ok
      (RepetitiveInterval.RepeatUnit.DAY == repetitiveInterval2.getRepeatUnit());

    var repetitiveInterval3 = new RepetitiveInterval
      (Common.fromIsoString("20150825T000000"),
       Common.fromIsoString("20151227T000000"), 5, 10, 2,
       RepetitiveInterval.RepeatUnit.MONTH);

    assert.ok(2 == repetitiveInterval3.getNRepeats());
    assert.ok
      (RepetitiveInterval.RepeatUnit.MONTH == repetitiveInterval3.getRepeatUnit());

    var repetitiveInterval4 = new RepetitiveInterval
      (Common.fromIsoString("20150825T000000"),
       Common.fromIsoString("20301227T000000"), 5, 10, 5,
       RepetitiveInterval.RepeatUnit.YEAR);

    assert.ok(5 == repetitiveInterval4.getNRepeats());
    assert.ok
      (RepetitiveInterval.RepeatUnit.YEAR == repetitiveInterval4.getRepeatUnit());

    var repetitiveInterval5 = new RepetitiveInterval();

    assert.ok(0 == repetitiveInterval5.getNRepeats());
    assert.ok
      (RepetitiveInterval.RepeatUnit.NONE == repetitiveInterval5.getRepeatUnit());
  });

  it('CoverTimePoint', function() {
    ///////////////////////////////////////////// With the repeat unit DAY.

    var repetitiveInterval1 = new RepetitiveInterval
      (Common.fromIsoString("20150825T000000"),
       Common.fromIsoString("20150925T000000"), 5, 10, 2,
       RepetitiveInterval.RepeatUnit.DAY);
    var result;

    var timePoint1 = Common.fromIsoString("20150825T050000");

    result = repetitiveInterval1.getInterval(timePoint1);
    assert.ok(true == result.isPositive);
    assert.ok("20150825T050000" == Common.toIsoString(result.interval.getStartTime()));
    assert.ok("20150825T100000" == Common.toIsoString(result.interval.getEndTime()));

    var timePoint2 = Common.fromIsoString("20150902T060000");

    result = repetitiveInterval1.getInterval(timePoint2);
    assert.ok(true == result.isPositive);
    assert.ok("20150902T050000" == Common.toIsoString(result.interval.getStartTime()));
    assert.ok("20150902T100000" == Common.toIsoString(result.interval.getEndTime()));

    var timePoint3 = Common.fromIsoString("20150929T040000");

    result = repetitiveInterval1.getInterval(timePoint3);
    assert.ok(false == result.isPositive);

    ///////////////////////////////////////////// With the repeat unit MONTH.

    var repetitiveInterval2 = new RepetitiveInterval
      (Common.fromIsoString("20150825T000000"),
       Common.fromIsoString("20160825T000000"), 5, 10, 2,
       RepetitiveInterval.RepeatUnit.MONTH);

    var timePoint4 = Common.fromIsoString("20150825T050000");

    result = repetitiveInterval2.getInterval(timePoint4);
    assert.ok(true == result.isPositive);
    assert.ok("20150825T050000" == Common.toIsoString(result.interval.getStartTime()));
    assert.ok("20150825T100000" == Common.toIsoString(result.interval.getEndTime()));

    var timePoint5 = Common.fromIsoString("20151025T060000");

    result = repetitiveInterval2.getInterval(timePoint5);
    assert.ok(true == result.isPositive);
    assert.ok("20151025T050000" == Common.toIsoString(result.interval.getStartTime()));
    assert.ok("20151025T100000" == Common.toIsoString(result.interval.getEndTime()));

    var timePoint6 = Common.fromIsoString("20151226T050000");

    result = repetitiveInterval2.getInterval(timePoint6);
    assert.ok(false == result.isPositive);

    var timePoint7 = Common.fromIsoString("20151225T040000");

    result = repetitiveInterval2.getInterval(timePoint7);
    assert.ok(false == result.isPositive);

    ///////////////////////////////////////////// With the repeat unit YEAR.

    var repetitiveInterval3 = new RepetitiveInterval
      (Common.fromIsoString("20150825T000000"),
       Common.fromIsoString("20300825T000000"), 5, 10, 3,
       RepetitiveInterval.RepeatUnit.YEAR);

    var timePoint8 = Common.fromIsoString("20150825T050000");

    result = repetitiveInterval3.getInterval(timePoint8);
    assert.ok(true == result.isPositive);
    assert.ok("20150825T050000" == Common.toIsoString(result.interval.getStartTime()));
    assert.ok("20150825T100000" == Common.toIsoString(result.interval.getEndTime()));

    var timePoint9 = Common.fromIsoString("20180825T060000");

    result = repetitiveInterval3.getInterval(timePoint9);
    assert.ok(true == result.isPositive);
    assert.ok("20180825T050000" == Common.toIsoString(result.interval.getStartTime()));
    assert.ok("20180825T100000" == Common.toIsoString(result.interval.getEndTime()));

    var timePoint10 = Common.fromIsoString("20180826T050000");
    result = repetitiveInterval3.getInterval(timePoint10);
    assert.ok(false == result.isPositive);

    var timePoint11 = Common.fromIsoString("20210825T040000");
    result = repetitiveInterval3.getInterval(timePoint11);
    assert.ok(false == result.isPositive);

    var timePoint12 = Common.fromIsoString("20300825T040000");
    result = repetitiveInterval3.getInterval(timePoint12);
    assert.ok(false == result.isPositive);
  });
});
