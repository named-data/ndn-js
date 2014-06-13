/*
 * Copyright (C) 2014 Regents of the University of California.
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
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

var Name = require('../..').Name;
var Interest = require('../..').Interest;
var Exclude = require('../..').Exclude;
console.log("typeof " + typeof true);

var name = new Name('/wentao.shang/test001');
var interest = new Interest(name);
interest.answerOriginKind = Interest.ANSWER_NO_CONTENT_STORE;
interest.interestLifetime = 1234;

// Note: this filter is meaningless, just for test purposes.
var filter = new Exclude
  ([Name.fromEscapedString('before'), Exclude.ANY, new Buffer('after', 'ascii'), Exclude.ANY, Name.fromEscapedString('%00%10')]);
interest.exclude = filter;

console.log('Interest with random Exclude:');
console.log(interest.toUri());

// Test Exlucde.matches()
var filter1 = new Exclude([Name.fromEscapedString('%00%02'), Exclude.ANY, Name.fromEscapedString('%00%20')]);
console.log('Meaningful Exclude:');
console.log(filter1.toUri());

var comp1 = Name.fromEscapedString('%00%01');
var comp2 = Name.fromEscapedString('%00%0F');
console.log('Matches:');
console.log(Name.toEscapedString(comp1) + ' ? ' + filter1.matches(comp1));
console.log(Name.toEscapedString(comp2) + ' ? ' + filter1.matches(comp2));
