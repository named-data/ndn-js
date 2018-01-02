/**
 * Copyright (C) 2014-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From PyNDN boost_info_parser by Adeola Bannis.
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
var fs = require('fs');

/**
 * BoostInfoTree is provided for compatibility with the Boost INFO property list
 * format used in ndn-cxx.
 *
 * Each node in the tree may have a name and a value as well as associated
 * sub-trees. The sub-tree names are not unique, and so sub-trees are stored as
 * dictionaries where the key is a sub-tree name and the values are the
 * sub-trees sharing the same name.
 *
 * Nodes can be accessed with a path syntax, as long as nodes in the path do not
 * contain the path separator '/' in their names.
 * @constructor
 */
var BoostInfoTree = function BoostInfoTree(value, parent)
{
  // subtrees is an array of {key: treeName, value: subtreeList} where
  // treeName is a string and subtreeList is an array of BoostInfoTree.
  // We can't use a dictionary because we want the keys to be in order.
  this.subtrees = [];
  this.value = value;
  this.parent = parent;

  this.lastChild = null;
};

/**
 * Insert a BoostInfoTree as a sub-tree with the given name.
 * @param {string} treeName The name of the new sub-tree.
 * @param {BoostInfoTree} newTree The sub-tree to add.
 */
BoostInfoTree.prototype.addSubtree = function(treeName, newTree)
{
  var subtreeList = this.find(treeName);
  if (subtreeList !== null)
    subtreeList.push(newTree);
  else
    this.subtrees.push({key: treeName, value: [newTree]});

  newTree.parent = this;
  this.lastChild = newTree;
};

/**
 * Create a new BoostInfo and insert it as a sub-tree with the given name.
 * @param {string} treeName The name of the new sub-tree.
 * @param {string} value The value associated with the new sub-tree.
 * @return {BoostInfoTree} The created sub-tree.
 */
BoostInfoTree.prototype.createSubtree = function(treeName, value)
{
  var newTree = new BoostInfoTree(value, this);
  this.addSubtree(treeName, newTree);
  return newTree;
};

/**
 * Look up using the key and return a list of the subtrees.
 * @param {string} key The key which may be a path separated with '/'.
 * @return {Array<BoostInfoTree>} A new array with pointers to the subtrees.
 */
BoostInfoTree.prototype.get = function(key)
{
  // Strip beginning '/'.
  key = key.replace(/^\/+/, "");
  if (key.length === 0)
    return [this];
  var path = key.split('/');

  var subtrees = this.find(path[0]);
  if (subtrees === null)
    return [];
  if (path.length == 1)
    return subtrees.slice(0);

  var newPath = path.slice(1).join('/');
  var foundVals = [];
  for (var i = 0; i < subtrees.length; ++i) {
    var t = subtrees[i];
    var partial = t.get(newPath);
    foundVals = foundVals.concat(partial);
  }
  return foundVals;
};

/**
 * Look up using the key and return string value of the first subtree.
 * @param {string} key The key which may be a path separated with '/'.
 * @return {string} The string value or null if not found.
 */
BoostInfoTree.prototype.getFirstValue = function(key)
{
  var list = this.get(key);
  if (list.length >= 1)
    return list[0].value;
  else
    return null;
};

BoostInfoTree.prototype.getValue = function() { return this.value; };

BoostInfoTree.prototype.getParent = function() { return this.parent; };

BoostInfoTree.prototype.getLastChild = function() { return this.lastChild; };

BoostInfoTree.prototype.prettyPrint = function(indentLevel)
{
  indentLevel = indentLevel || 1;

  var prefix = Array(indentLevel + 1).join(' ');
  var s = "";

  if (this.parent != null) {
    if (this.value && this.value.length > 0)
      s += "\"" + this.value + "\"";
    s += "\n";
  }

  if (this.subtrees.length > 0) {
    if (this.parent)
      s += prefix + "{\n";
    var nextLevel = Array(indentLevel + 2 + 1).join(' ');
    for (var i = 0; i < this.subtrees.length; ++i) {
      for (var iSubTree = 0; iSubTree < this.subtrees[i].value.length; ++iSubTree)
        s += nextLevel + this.subtrees[i].key + " " +
             this.subtrees[i].value[iSubTree].prettyPrint(indentLevel + 2);
    }

    if (this.parent)
      s +=  prefix + "}\n";
  }

  return s;
};

BoostInfoTree.prototype.toString = function()
{
  return this.prettyPrint();
};

/**
 * Use treeName to find the array of BoostInfoTree in this.subtrees.
 * @param {string} treeName The key in this.subtrees to search for. This does a
 * flat search in subtrees_.  It does not split by '/' into a path.
 * @return {Array<BoostInfoTree>} A array of BoostInfoTree, or null if not found.
 */
BoostInfoTree.prototype.find = function(treeName)
{
  for (var i = 0; i < this.subtrees.length; ++i) {
    if (this.subtrees[i].key == treeName)
      return this.subtrees[i].value;
  }

  return null;
};

/**
 * A BoostInfoParser reads files in Boost's INFO format and constructs a
 * BoostInfoTree.
 * @constructor
 */
var BoostInfoParser = function BoostInfoParser()
{
  this.root = new BoostInfoTree();
};

exports.BoostInfoParser = BoostInfoParser;
exports.BoostInfoTree = BoostInfoTree; // debug

/**
 * Add the contents of the file or input string to the root BoostInfoTree. There
 * are two forms:
 * read(fileName) reads fileName from the file system.
 * read(input, inputName) reads from the input, in which case inputName is used
 * only for log messages, etc.
 * @param {string} fileName The path to the INFO file.
 * @param {string} input The contents of the INFO file, with lines separated by
 * "\n" or "\r\n".
 * @param {string} inputName Use with input for log messages, etc.
 */
BoostInfoParser.prototype.read = function(fileNameOrInput, inputName)
{
  var input;
  if (typeof inputName == 'string')
    input = fileNameOrInput;
  else {
    // No inputName, so assume the first arg is the file name.
    var fileName = fileNameOrInput;
    inputName = fileName;
    input = fs.readFileSync(fileName).toString();
  }

  var ctx = this.root;
  var thisParser = this;
  input.split(/\r?\n/).forEach(function(line) {
    ctx = thisParser.parseLine(line.trim(), ctx);
  });
};

/**
 * Write the root tree of this BoostInfoParser as file in Boost's INFO format.
 * @param {string} fileName The output path.
 */
BoostInfoParser.prototype.write = function(fileName)
{
  fs.writeFileSync(fileName, "" + this.root);
};

/**
 * Get the root tree of this parser.
 * @return {BoostInfoTree} The root BoostInfoTree.
 */
BoostInfoParser.prototype.getRoot = function() { return this.root; };

/**
 * Similar to Python's shlex.split, split s into an array of strings which are
 * separated by whitespace, treating a string within quotes as a single entity
 * regardless of whitespace between the quotes. Also allow a backslash to escape
 * the next character.
 * @param {string} s The input string to split.
 * @return {Array<string>} An array of strings.
 */
BoostInfoParser.shlex_split = function(s)
{
  var result = [];
  if (s == "")
    return result;
  var whiteSpace = " \t\n\r";
  var iStart = 0;

  while (true) {
    // Move iStart past whitespace.
    while (whiteSpace.indexOf(s[iStart]) >= 0) {
      iStart += 1;
      if (iStart >= s.length)
        // Done.
        return result;
    }

    // Move iEnd to the end of the token.
    var iEnd = iStart;
    var inQuotation = false;
    var token = "";
    while (true) {
      if (s[iEnd] == '\\') {
        // Append characters up to the backslash, skip the backslash and
        //   move iEnd past the escaped character.
        token += s.substring(iStart, iEnd);
        iStart = iEnd + 1;
        iEnd = iStart;
        if (iEnd >= s.length)
          // An unusual case: A backslash at the end of the string.
          break;
      }
      else {
        if (inQuotation) {
          if (s[iEnd] == '\"') {
            // Append characters up to the end quote and skip.
            token += s.substring(iStart, iEnd);
            iStart = iEnd + 1;
            inQuotation = false;
          }
        }
        else {
          if (s[iEnd] == '\"') {
            // Append characters up to the start quote and skip.
            token += s.substring(iStart, iEnd);
            iStart = iEnd + 1;
            inQuotation = true;
          }
          else
            if (whiteSpace.indexOf(s[iEnd]) >= 0)
              break;
        }
      }

      iEnd += 1;
      if (iEnd >= s.length)
        break;
    }

    token += s.substring(iStart, iEnd);
    result.push(token);
    if (iEnd >= s.length)
      // Done.
      return result;

    iStart = iEnd;
  }
};

BoostInfoParser.prototype.parseLine = function(line, context)
{
  // Skip blank lines and comments.
  var commentStart = line.indexOf(';');
  if (commentStart >= 0)
    line = line.substring(0, commentStart).trim();
  if (line.length == 0)
    return context;

  // Usually we are expecting key and optional value.
  var strings = BoostInfoParser.shlex_split(line);
  var isSectionStart = false;
  var isSectionEnd = false;
  for (var i = 0; i < strings.length; ++i) {
    isSectionStart = (isSectionStart || strings[i] == "{");
    isSectionEnd = (isSectionEnd || strings[i] == "}");
  }

  if (!isSectionStart && !isSectionEnd) {
    var key = strings[0];
    var val;
    if (strings.length > 1)
      val = strings[1];
    context.createSubtree(key, val);

    return context;
  }

  // OK, who is the joker who put a { on the same line as the key name?!
  var sectionStart = line.indexOf('{');
  if (sectionStart > 0) {
    var firstPart = line.substring(0, sectionStart);
    var secondPart = line.substring(sectionStart);

    var ctx = this.parseLine(firstPart, context);
    return this.parseLine(secondPart, ctx);
  }

  // If we encounter a {, we are beginning a new context.
  // TODO: Error if there was already a subcontext here.
  if (line[0] == '{') {
    context = context.getLastChild();
    return context;
  }

  // If we encounter a }, we are ending a list context.
  if (line[0] == '}') {
    context = context.getParent();
    return context;
  }

  throw runtime_error("BoostInfoParser: input line is malformed");
};
