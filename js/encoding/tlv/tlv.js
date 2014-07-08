/**
 * Copyright (C) 2014 Regents of the University of California.
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
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

/**
 * The Tlv class has static type codes for the NDN-TLV wire format.
 * @constructor
 */
var Tlv = function Tlv()
{
};

exports.Tlv = Tlv;

Tlv.Interest =         5;
Tlv.Data =             6;
Tlv.Name =             7;
Tlv.NameComponent =    8;
Tlv.Selectors =        9;
Tlv.Nonce =            10;
Tlv.Scope =            11;
Tlv.InterestLifetime = 12;
Tlv.MinSuffixComponents = 13;
Tlv.MaxSuffixComponents = 14;
Tlv.PublisherPublicKeyLocator = 15;
Tlv.Exclude =          16;
Tlv.ChildSelector =    17;
Tlv.MustBeFresh =      18;
Tlv.Any =              19;
Tlv.MetaInfo =         20;
Tlv.Content =          21;
Tlv.SignatureInfo =    22;
Tlv.SignatureValue =   23;
Tlv.ContentType =      24;
Tlv.FreshnessPeriod =  25;
Tlv.FinalBlockId =     26;
Tlv.SignatureType =    27;
Tlv.KeyLocator =       28;
Tlv.KeyLocatorDigest = 29;
Tlv.FaceInstance =     128;
Tlv.ForwardingEntry =  129;
Tlv.StatusResponse =   130;
Tlv.Action =           131;
Tlv.FaceID =           132;
Tlv.IPProto =          133;
Tlv.Host =             134;
Tlv.Port =             135;
Tlv.MulticastInterface = 136;
Tlv.MulticastTTL =     137;
Tlv.ForwardingFlags =  138;
Tlv.StatusCode =       139;
Tlv.StatusText =       140;

Tlv.SignatureType_DigestSha256 = 0;
Tlv.SignatureType_SignatureSha256WithRsa = 1;
