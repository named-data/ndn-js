/**
 * Copyright (C) 2014-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
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
var TlvEncoder = require('./tlv/tlv-encoder.js').TlvEncoder; /** @ignore */
var TlvDecoder = require('./tlv/tlv-decoder.js').TlvDecoder; /** @ignore */
var Blob = require('../util/blob.js').Blob; /** @ignore */
var Name = require('../name.js').Name; /** @ignore */

/**
 * ProtobufTlv has static methods to encode and decode an Protobuf Message
 * object as NDN-TLV. The Protobuf tag value is used as the TLV type code. A
 * Protobuf message is encoded/decoded as a nested TLV encoding. Protobuf types
 * uint32, uint64 and enum are encoded/decoded as TLV nonNegativeInteger. (It is
 * an error if an enum value is negative.) Protobuf types bytes and string are
 * encoded/decoded as TLV bytes. The Protobuf type bool is encoded/decoded as a
 * TLV boolean (a zero length value for True, omitted for False). The Protobuf
 * type double is encoded/decoded as an 8-byte little-endian IEEE 754 double.
 * Other Protobuf types are an error.
 *
 * Protobuf has no "outer" message type, so you need to put your TLV message
 * inside an outer "typeless" message.
 * @constructor
 */
var ProtobufTlv = function ProtobufTlv()
{
};

exports.ProtobufTlv = ProtobufTlv;

// Load ProtoBuf.Reflect.Message.Field dynamically so that protobufjs is optional.
ProtobufTlv._Field = null;
ProtobufTlv.establishField = function()
{
  if (ProtobufTlv._Field === null) {
    try {
      // Using protobuf.min.js in the browser.
      ProtobufTlv._Field = dcodeIO.ProtoBuf.Reflect.Message.Field;
    }
    catch (ex) {
      // Using protobufjs in node.
      ProtobufTlv._Field = require("protobufjs").Reflect.Message.Field;
    }
  }
}

/**
 * Encode the Protobuf message object as NDN-TLV. This calls
 * message.encodeAB() to ensure that all required fields are present and
 * raises an exception if not. (This does not use the result of toArrayBuffer().)
 * @param {ProtoBuf.Builder.Message} message The Protobuf message object.
 * @param {ProtoBuf.Reflect.T} descriptor The reflection descriptor for the
 * message. For example, if the message is of type "MyNamespace.MyMessage" then
 * the descriptor is builder.lookup("MyNamespace.MyMessage").
 * @return {Blob} The encoded buffer in a Blob object.
 */
ProtobufTlv.encode = function(message, descriptor)
{
  ProtobufTlv.establishField();

  message.encodeAB();
  var encoder = new TlvEncoder();
  ProtobufTlv._encodeMessageValue(message, descriptor, encoder);
  return new Blob(encoder.getOutput(), false);
};

/**
 * Decode the input as NDN-TLV and update the fields of the Protobuf message
 * object.
 * @param {ProtoBuf.Builder.Message} message The Protobuf message object. This
 * does not first clear the object.
 * @param {ProtoBuf.Reflect.T} descriptor The reflection descriptor for the
 * message. For example, if the message is of type "MyNamespace.MyMessage" then
 * the descriptor is builder.lookup("MyNamespace.MyMessage").
 * @param {Blob|Buffer} input The buffer with the bytes to decode.
 */
ProtobufTlv.decode = function(message, descriptor, input)
{
  ProtobufTlv.establishField();

  // If input is a blob, get its buf().
  var decodeBuffer = typeof input === 'object' && input instanceof Blob ?
                     input.buf() : input;

  var decoder = new TlvDecoder(decodeBuffer);
  ProtobufTlv._decodeMessageValue
    (message, descriptor, decoder, decodeBuffer.length);
};

ProtobufTlv._encodeMessageValue = function(message, descriptor, encoder)
{
  var fields = descriptor.getChildren(ProtobufTlv._Field);
  // Encode the fields backwards.
  for (var iField = fields.length - 1; iField >= 0; --iField) {
    var field = fields[iField];
    var tlvType = field.id;

    var values;
    if (field.repeated)
      values = message[field.name];
    else {
      if (message[field.name] != null)
        // Make a singleton list.
        values = [message[field.name]];
      else
        continue;
    }

    // Encode the values backwards.
    for (var iValue = values.length - 1; iValue >= 0; --iValue) {
      var value = values[iValue];

      if (field.type.name == "message") {
        var saveLength =  encoder.getLength();

        // Encode backwards.
        ProtobufTlv._encodeMessageValue(value, field.resolvedType, encoder);
        encoder.writeTypeAndLength(tlvType, encoder.getLength() - saveLength);
      }
      else if (field.type.name == "uint32" ||
               field.type.name == "uint64")
        encoder.writeNonNegativeIntegerTlv(tlvType, value);
      else if (field.type.name == "enum") {
        if (value < 0)
          throw new Error("ProtobufTlv.encode: ENUM value may not be negative");
        encoder.writeNonNegativeIntegerTlv(tlvType, value);
      }
      else if (field.type.name == "bytes") {
        var buffer = value.toBuffer();
        if (buffer.length == undefined)
          // We are not running in Node.js, so assume we are using the dcodeIO
          // browser implementation based on ArrayBuffer.
          buffer = new Uint8Array(value.toArrayBuffer());
        encoder.writeBlobTlv(tlvType, buffer);
      }
      else if (field.type.name == "string")
        // Use Blob to convert.
        encoder.writeBlobTlv(tlvType, new Blob(value, false).buf());
      else if (field.type.name == "bool") {
        if (value)
          encoder.writeTypeAndLength(tlvType, 0);
      }
      else if (field.type.name == "double") {
        var encoding = new Buffer(8);
        encoding.writeDoubleLE(value, 0);
        encoder.writeBlobTlv(tlvType, encoding);
      }
      else
        throw new Error("ProtobufTlv.encode: Unknown field type");
    }
  }
};

ProtobufTlv._decodeMessageValue = function(message, descriptor, decoder, endOffset)
{
  var fields = descriptor.getChildren(ProtobufTlv._Field);
  for (var iField = 0; iField < fields.length; ++iField) {
    var field = fields[iField];
    var tlvType = field.id;

    if (!field.required && !decoder.peekType(tlvType, endOffset))
      continue;

    if (field.repeated) {
      while (decoder.peekType(tlvType, endOffset)) {
        if (field.type.name == "message") {
          var innerEndOffset = decoder.readNestedTlvsStart(tlvType);
          var value = new (field.resolvedType.build())();
          message.add(field.name, value);
          ProtobufTlv._decodeMessageValue
            (value, field.resolvedType, decoder, innerEndOffset);
          decoder.finishNestedTlvs(innerEndOffset);
        }
        else
          message.add
            (field.name,
             ProtobufTlv._decodeFieldValue(field, tlvType, decoder, endOffset));
      }
    }
    else {
      if (field.type.name == "message") {
        var innerEndOffset = decoder.readNestedTlvsStart(tlvType);
        var value = new (field.resolvedType.build())();
        message.set(field.name, value);
        ProtobufTlv._decodeMessageValue
          (value, field.resolvedType, decoder, innerEndOffset);
        decoder.finishNestedTlvs(innerEndOffset);
      }
      else
        message.set
          (field.name,
           ProtobufTlv._decodeFieldValue(field, tlvType, decoder, endOffset));
    }
  }
};

/**
 * This is a helper for _decodeMessageValue. Decode a single field and return
 * the value. Assume the field.type.name is not "message".
 */
ProtobufTlv._decodeFieldValue = function(field, tlvType, decoder, endOffset)
{
  if (field.type.name == "uint32" ||
      field.type.name == "uint64" ||
      field.type.name == "enum")
    return decoder.readNonNegativeIntegerTlv(tlvType);
  else if (field.type.name == "bytes")
    return decoder.readBlobTlv(tlvType);
  else if (field.type.name == "string")
    return decoder.readBlobTlv(tlvType).toString();
  else if (field.type.name == "bool")
    return decoder.readBooleanTlv(tlvType, endOffset);
  else if (field.type.name == "double")
    return decoder.readBlobTlv(tlvType).readDoubleLE(0);
  else
    throw new Error("ProtobufTlv.decode: Unknown field type");
};

/**
 * Return a Name made from the component array in a Protobuf message object,
 * assuming that it was defined with "repeated bytes". For example:
 * message Name {
 *   repeated bytes component = 8;
 * }
 * @param {Array} componentArray The array from the Protobuf message object
 * representing the "repeated bytes" component array.
 * @return A new Name.
 */
ProtobufTlv.toName = function(componentArray)
{
  var name = new Name();
  for (var i = 0; i < componentArray.length; ++i)
    name.append
      (new Blob(new Buffer(componentArray[i].toBinary(), "binary"), false));

  return name;
};
