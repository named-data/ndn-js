/**
 * Copyright (C) 2015-2016 Regents of the University of California.
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
    assert.equal(Common.toIsoString(repetitiveInterval1.getStartDate()), "20150825T000000");
    assert.equal(Common.toIsoString(repetitiveInterval1.getEndDate()), "20150825T000000");
    assert.equal(repetitiveInterval1.getIntervalStartHour(), 5);
    assert.equal(repetitiveInterval1.getIntervalEndHour(), 10);

    var repetitiveInterval2 = new RepetitiveInterval
      (Common.fromIsoString("20150825T000000"),
       Common.fromIsoString("20150827T000000"), 5, 10, 1,
       RepetitiveInterval.RepeatUnit.DAY);

    assert.equal(repetitiveInterval2.getNRepeats(), 1);
    assert.equal
      (repetitiveInterval2.getRepeatUnit(), RepetitiveInterval.RepeatUnit.DAY);

    var repetitiveInterval3 = new RepetitiveInterval
      (Common.fromIsoString("20150825T000000"),
       Common.fromIsoString("20151227T000000"), 5, 10, 2,
       RepetitiveInterval.RepeatUnit.MONTH);

    assert.equal(repetitiveInterval3.getNRepeats(), 2);
    assert.equal
      (repetitiveInterval3.getRepeatUnit(), RepetitiveInterval.RepeatUnit.MONTH);

    var repetitiveInterval4 = new RepetitiveInterval
      (Common.fromIsoString("20150825T000000"),
       Common.fromIsoString("20301227T000000"), 5, 10, 5,
       RepetitiveInterval.RepeatUnit.YEAR);

    assert.equal(repetitiveInterval4.getNRepeats(), 5);
    assert.equal
      (repetitiveInterval4.getRepeatUnit(), RepetitiveInterval.RepeatUnit.YEAR);

    var repetitiveInterval5 = new RepetitiveInterval();

    assert.equal(repetitiveInterval5.getNRepeats(), 0);
    assert.equal
      (repetitiveInterval5.getRepeatUnit(), RepetitiveInterval.RepeatUnit.NONE);
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
    assert.equal(result.isPositive, true);
    assert.equal(Common.toIsoString(result.interval.getStartTime()), "20150825T050000");
    assert.equal(Common.toIsoString(result.interval.getEndTime()), "20150825T100000");

    var timePoint2 = Common.fromIsoString("20150902T060000");

    result = repetitiveInterval1.getInterval(timePoint2);
    assert.equal(result.isPositive, true);
    assert.equal(Common.toIsoString(result.interval.getStartTime()), "20150902T050000");
    assert.equal(Common.toIsoString(result.interval.getEndTime()), "20150902T100000");

    var timePoint3 = Common.fromIsoString("20150929T040000");

    result = repetitiveInterval1.getInterval(timePoint3);
    assert.equal(result.isPositive, false);

    ///////////////////////////////////////////// With the repeat unit MONTH.

    var repetitiveInterval2 = new RepetitiveInterval
      (Common.fromIsoString("20150825T000000"),
       Common.fromIsoString("20160825T000000"), 5, 10, 2,
       RepetitiveInterval.RepeatUnit.MONTH);

    var timePoint4 = Common.fromIsoString("20150825T050000");

    result = repetitiveInterval2.getInterval(timePoint4);
    assert.equal(result.isPositive, true);
    assert.equal(Common.toIsoString(result.interval.getStartTime()), "20150825T050000");
    assert.equal(Common.toIsoString(result.interval.getEndTime()), "20150825T100000");

    var timePoint5 = Common.fromIsoString("20151025T060000");

    result = repetitiveInterval2.getInterval(timePoint5);
    assert.equal(result.isPositive, true);
    assert.equal(Common.toIsoString(result.interval.getStartTime()), "20151025T050000");
    assert.equal(Common.toIsoString(result.interval.getEndTime()), "20151025T100000");

    var timePoint6 = Common.fromIsoString("20151226T050000");

    result = repetitiveInterval2.getInterval(timePoint6);
    assert.equal(result.isPositive, false);

    var timePoint7 = Common.fromIsoString("20151225T040000");

    result = repetitiveInterval2.getInterval(timePoint7);
    assert.equal(result.isPositive, false);

    ///////////////////////////////////////////// With the repeat unit YEAR.

    var repetitiveInterval3 = new RepetitiveInterval
      (Common.fromIsoString("20150825T000000"),
       Common.fromIsoString("20300825T000000"), 5, 10, 3,
       RepetitiveInterval.RepeatUnit.YEAR);

    var timePoint8 = Common.fromIsoString("20150825T050000");

    result = repetitiveInterval3.getInterval(timePoint8);
    assert.equal(result.isPositive, true);
    assert.equal(Common.toIsoString(result.interval.getStartTime()), "20150825T050000");
    assert.equal(Common.toIsoString(result.interval.getEndTime()), "20150825T100000");

    var timePoint9 = Common.fromIsoString("20180825T060000");

    result = repetitiveInterval3.getInterval(timePoint9);
    assert.equal(result.isPositive, true);
    assert.equal(Common.toIsoString(result.interval.getStartTime()), "20180825T050000");
    assert.equal(Common.toIsoString(result.interval.getEndTime()), "20180825T100000");

    var timePoint10 = Common.fromIsoString("20180826T050000");
    result = repetitiveInterval3.getInterval(timePoint10);
    assert.equal(result.isPositive, false);

    var timePoint11 = Common.fromIsoString("20210825T040000");
    result = repetitiveInterval3.getInterval(timePoint11);
    assert.equal(result.isPositive, false);

    var timePoint12 = Common.fromIsoString("20300825T040000");
    result = repetitiveInterval3.getInterval(timePoint12);
    assert.equal(result.isPositive, false);
  });

  it('Comparison', function() {
    function check(small, big)
    {
      return small.compare(big) < 0 && !(big.compare(small) < 0);
    }

    assert.ok(check(new RepetitiveInterval(Common.fromIsoString("20150825T000000"),
                                           Common.fromIsoString("20150828T000000"),
                                        5, 10, 2, RepetitiveInterval.RepeatUnit.DAY),
                    new RepetitiveInterval(Common.fromIsoString("20150826T000000"),
                                           Common.fromIsoString("20150828T000000"),
                                        5, 10, 2, RepetitiveInterval.RepeatUnit.DAY)));

    assert.ok(check(new RepetitiveInterval(Common.fromIsoString("20150825T000000"),
                                           Common.fromIsoString("20150828T000000"),
                                        5, 10, 2, RepetitiveInterval.RepeatUnit.DAY),
                    new RepetitiveInterval(Common.fromIsoString("20150825T000000"),
                                           Common.fromIsoString("20150828T000000"),
                                        6, 10, 2, RepetitiveInterval.RepeatUnit.DAY)));

    assert.ok(check(new RepetitiveInterval(Common.fromIsoString("20150825T000000"),
                                           Common.fromIsoString("20150828T000000"),
                                        5, 10, 2, RepetitiveInterval.RepeatUnit.DAY),
                    new RepetitiveInterval(Common.fromIsoString("20150825T000000"),
                                           Common.fromIsoString("20150828T000000"),
                                        5, 11, 2, RepetitiveInterval.RepeatUnit.DAY)));

    assert.ok(check(new RepetitiveInterval(Common.fromIsoString("20150825T000000"),
                                           Common.fromIsoString("20150828T000000"),
                                        5, 10, 2, RepetitiveInterval.RepeatUnit.DAY),
                    new RepetitiveInterval(Common.fromIsoString("20150825T000000"),
                                           Common.fromIsoString("20150828T000000"),
                                        5, 10, 3, RepetitiveInterval.RepeatUnit.DAY)));

    assert.ok(check(new RepetitiveInterval(Common.fromIsoString("20150825T000000"),
                                           Common.fromIsoString("20150828T000000"),
                                        5, 10, 2, RepetitiveInterval.RepeatUnit.DAY),
                    new RepetitiveInterval(Common.fromIsoString("20150825T000000"),
                                           Common.fromIsoString("20150828T000000"),
                                        5, 10, 2, RepetitiveInterval.RepeatUnit.MONTH)));
  });
});
