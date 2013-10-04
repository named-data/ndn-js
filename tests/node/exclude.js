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
