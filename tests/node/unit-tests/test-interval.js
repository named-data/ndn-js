/**
 * Copyright (C) 2015-2016 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt unit tests
 * https://github.com/named-data/ndn-group-encrypt/blob/master/tests/unit-tests/interval.t.cpp
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
var Interval = require('../../..').Interval;
var Common = require('./unit-tests-common.js').UnitTestsCommon;

describe('TestInterval', function() {
  it('Construction', function() {
    // Construct with the right parameters.
    var interval1 = new Interval(Common.fromIsoString("20150825T120000"),
                                 Common.fromIsoString("20150825T160000"));
    assert.equal(Common.toIsoString(interval1.getStartTime()), "20150825T120000");
    assert.equal(Common.toIsoString(interval1.getEndTime()), "20150825T160000");
    assert.ok(interval1.isValid());

    // Construct with the invalid interval.
    var interval2 = new Interval();
    assert.ok(!interval2.isValid());

    // Construct with the empty interval.
    var interval3 = new Interval(true);
    assert.ok(interval3.isValid());
    assert.ok(interval3.isEmpty());
  });

  it('CoverTimePoint', function() {
    var interval = new Interval(Common.fromIsoString("20150825T120000"),
                                Common.fromIsoString("20150825T160000"));

    var timePoint1 = Common.fromIsoString("20150825T120000");
    var timePoint2 = Common.fromIsoString("20150825T130000");
    var timePoint3 = Common.fromIsoString("20150825T170000");
    var timePoint4 = Common.fromIsoString("20150825T110000");

    assert.ok(interval.covers(timePoint1));
    assert.ok(interval.covers(timePoint2));
    assert.ok(!interval.covers(timePoint3));
    assert.ok(!interval.covers(timePoint4));
  });

  it('IntersectionAndUnion', function() {
    var interval1 = new Interval(Common.fromIsoString("20150825T030000"),
                                 Common.fromIsoString("20150825T050000"));
    // No intersection.
    var interval2 = new Interval(Common.fromIsoString("20150825T050000"),
                                 Common.fromIsoString("20150825T070000"));
    // No intersection.
    var interval3 = new Interval(Common.fromIsoString("20150825T060000"),
                                 Common.fromIsoString("20150825T070000"));
    // There's an intersection.
    var interval4 = new Interval(Common.fromIsoString("20150825T010000"),
                                 Common.fromIsoString("20150825T040000"));
    // Right in interval1, there's an intersection.
    var interval5 = new Interval(Common.fromIsoString("20150825T030000"),
                                 Common.fromIsoString("20150825T040000"));
    // Wrap interval1, there's an intersection.
    var interval6 = new Interval(Common.fromIsoString("20150825T010000"),
                                 Common.fromIsoString("20150825T050000"));
    // Empty interval.
    var interval7 = new Interval(true);

    var tempInterval = new Interval(interval1);
    tempInterval.intersectWith(interval2);
    assert.ok(tempInterval.isEmpty());

    tempInterval = new Interval(interval1);
    var gotError = true;
    try {
      tempInterval.unionWith(interval2);
      gotError = false;
    } catch (ex) {}
    if (!gotError)
      assert.fail('', '', "Expected error in unionWith(interval2)");

    tempInterval = new Interval(interval1);
    tempInterval.intersectWith(interval3);
    assert.ok(tempInterval.isEmpty());

    tempInterval = new Interval(interval1);
    gotError = true;
    try {
      tempInterval.unionWith(interval3);
      gotError = false;
    } catch (ex) {}
    if (!gotError)
      assert.fail('', '', "Expected error in unionWith(interval3)");

    tempInterval = new Interval(interval1);
    tempInterval.intersectWith(interval4);
    assert.ok(!tempInterval.isEmpty());
    assert.equal(Common.toIsoString(tempInterval.getStartTime()), "20150825T030000");
    assert.equal(Common.toIsoString(tempInterval.getEndTime()), "20150825T040000");

    tempInterval = new Interval(interval1);
    tempInterval.unionWith(interval4);
    assert.ok(!tempInterval.isEmpty());
    assert.equal(Common.toIsoString(tempInterval.getStartTime()), "20150825T010000");
    assert.equal(Common.toIsoString(tempInterval.getEndTime()), "20150825T050000");

    tempInterval = new Interval(interval1);
    tempInterval.intersectWith(interval5);
    assert.ok(!tempInterval.isEmpty());
    assert.equal(Common.toIsoString(tempInterval.getStartTime()), "20150825T030000");
    assert.equal(Common.toIsoString(tempInterval.getEndTime()), "20150825T040000");

    tempInterval = new Interval(interval1);
    tempInterval.unionWith(interval5);
    assert.ok(!tempInterval.isEmpty());
    assert.equal(Common.toIsoString(tempInterval.getStartTime()), "20150825T030000");
    assert.equal(Common.toIsoString(tempInterval.getEndTime()), "20150825T050000");

    tempInterval = new Interval(interval1);
    tempInterval.intersectWith(interval6);
    assert.ok(!tempInterval.isEmpty());
    assert.equal(Common.toIsoString(tempInterval.getStartTime()), "20150825T030000");
    assert.equal(Common.toIsoString(tempInterval.getEndTime()), "20150825T050000");

    tempInterval = new Interval(interval1);
    tempInterval.unionWith(interval6);
    assert.ok(!tempInterval.isEmpty());
    assert.equal(Common.toIsoString(tempInterval.getStartTime()), "20150825T010000");
    assert.equal(Common.toIsoString(tempInterval.getEndTime()), "20150825T050000");

    tempInterval = new Interval(interval1);
    tempInterval.intersectWith(interval7);
    assert.ok(tempInterval.isEmpty());

    tempInterval = new Interval(interval1);
    tempInterval.unionWith(interval7);
    assert.ok(!tempInterval.isEmpty());
    assert.equal(Common.toIsoString(tempInterval.getStartTime()), "20150825T030000");
    assert.equal(Common.toIsoString(tempInterval.getEndTime()), "20150825T050000");
  });
});
