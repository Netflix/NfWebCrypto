/*
 *
 *  Copyright 2013 Netflix, Inc.
 *
 *     Licensed under the Apache License, Version 2.0 (the "License");
 *     you may not use this file except in compliance with the License.
 *     You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *     Unless required by applicable law or agreed to in writing, software
 *     distributed under the License is distributed on an "AS IS" BASIS,
 *     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *     See the License for the specific language governing permissions and
 *     limitations under the License.
 *
 */
#ifndef Netflix_Base_Base64_h_
#define Netflix_Base_Base64_h_

#include <cstddef> // for std::size_t
#include <string>
#include <vector>
#include <stdint.h>
#include "StaticAssert.h"

namespace {
static signed char const CHAR_MAP[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static signed char const EQUAL = '=';
static signed char const PERIOD = '.';
} // namespace anonymous

namespace cadmium {
namespace base {
namespace Base64 {
namespace Private {

template <typename InputIterator_, typename OutputIterator_, std::size_t N_>
OutputIterator_ toBase64(InputIterator_ begin, InputIterator_ end,
    OutputIterator_ out,  signed char const (&table)[N_], signed char const pad) {
  STATIC_ASSERT((N_ >= 64)); // lookup table must be this big
  InputIterator_ p = begin;
  while (p != end) {
    signed char buf[4] = { pad, pad, pad, pad };
    uint8_t const v = static_cast<uint8_t>(*p);
    buf[0] = table[v >> 2];
    int index1 = (v & 0x3) << 4; // must defer
    if (++p != end) {
      uint8_t const v = static_cast<uint8_t>(*p);
      index1 |= v >> 4;
      int index2 = (v & 0xf) << 2; // must defer
      if (++p != end) {
        uint8_t const v = static_cast<uint8_t>(*p);
        index2 |= v >> 6;
        buf[3] = table[v & 0x3f];
        ++p;
      }
      buf[2] = table[index2];
    }
    buf[1] = table[index1];
    out = std::copy(buf, buf + sizeof buf, out);
  }
  return out;
}

template <typename InputIterator_, typename OutputIterator_>
OutputIterator_ fromBase64(InputIterator_ begin, InputIterator_ end,
    OutputIterator_ out) {
  static signed char const REVERSE[] = { // reverse LUT for base-64 decoding
      -1,-1,-1,-1,-1,-1,-1,-1,    -1,-1,99,-1,-1,99,-1,-1,
      -1,-1,-1,-1,-1,-1,-1,-1,    -1,-1,-1,-1,-1,-1,-1,-1,
    //    !  "  #  $  %  &  '      (  )  *  +  ,  -  .  /
      -1,-1,-1,-1,-1,-1,-1,-1,    -1,-1,-1,62,-1,62,-1,63,
    // 0  1  2  3  4  5  6  7      8  9  :  ;  <  =  >  ?
      52,53,54,55,56,57,58,59,    60,61,-1,-1,-1,-1,-1,-1,
    //    A  B  C  D  E  F  G      H  I  J  K  L  M  N  O
      -1, 0, 1, 2, 3, 4, 5, 6,     7, 8, 9,10,11,12,13,14,
    // P  Q  R  S  T  U  V  W      X  Y  Z  [  \  ]  ^  _
      15,16,17,18,19,20,21,22,    23,24,25,-1,-1,-1,-1,63,
    // @  a  b  c  d  e  f  g      h  i  j  k  l  m  n  o
      -1,26,27,28,29,30,31,32,    33,34,35,36,37,38,39,40,
    // p  q  r  s  t  u  v  w      x  y  z  {  |  }  ~
      41,42,43,44,45,46,47,48,    49,50,51,-1,-1,-1,-1,-1
  };

  InputIterator_ p = begin;
  while (p != end) {
    // Attempt to obtain 4 encoded bytes of information.
    int index[4] = { -1, -1, -1, -1 };
    for (int i = 0; i < 4 && p != end; ++i) {
      index[i] = REVERSE[*p++ & 0x7f];
      if (index[i] >= 64) { --i; continue; } // ignore certain whitespace
    }

    // Convert the 4 bytes of encoded information to 3 bytes of decoded
    // information.  Stop decoding at the first instance of -1.  Much of the
    // following code assumes incorrect input, which complicates things.
    if (index[0] < 0) break;
    { // artificial scoping
      bool const at_end = index[1] < 0;
      *out++ = (index[0] << 2) | (at_end ? 0 : (index[1] >> 4));
      if (at_end) break;
    }
    if (index[2] < 0) break;
    *out++ = ((index[1] & 0xf) << 4) | (index[2] >> 2);
    if (index[3] < 0) break;
    *out++ = ((index[2] & 0x3) << 6) | index[3];
  }
  return out;
}
}

/**
 * Return the result of a base-64 encoding operation on the range specified by
 * the supplied iterators.  This function generates a standard base-64
 * encoding.  The supplied input and output buffers should not overlap.
 * @param begin the beginning of the unencoded data.
 * @param end the end of the unencoded data.
 * @param out the target for the encoded result.
 * @return the end of the encoded result.
 */
template <typename InputIterator_, typename OutputIterator_>
OutputIterator_ encode(InputIterator_ begin, InputIterator_ end,
                       OutputIterator_ out)
{
    return Private::toBase64(begin, end, out, CHAR_MAP, EQUAL);
}

/**
 * Return the result of a base-64 decoding operation on the range specified by
 * the supplied iterators.  This function will successfully decode base-64
 * encodings that result from any encoding functions in this library.  The
 * supplied input and output buffers should not overlap.
 * @param begin the beginning of the encoded data.
 * @param end the end of the encoded data.
 * @param out the target for the decoded result.
 * @return the end of the decoded result.
 */
template <typename InputIterator_, typename OutputIterator_>
OutputIterator_ decode(InputIterator_ begin, InputIterator_ end,
                       OutputIterator_ out)
{
    return Private::fromBase64(begin, end, out);
}

/** This is a macro function for encode. */
std::string encode(std::string const& s);

/** This is a macro function for decode. */
std::string decode(std::string const& s);

/** This is a macro function for encode. */
std::vector<unsigned char> encode(std::vector<unsigned char> const& s);

/** This is a macro function for decode. */
std::vector<unsigned char> decode(std::vector<unsigned char> const& s);

/** URL-safe variants */
std::string encodeUrlSafe(std::string const& s);
std::string decodeUrlSafe(std::string const& s);
std::vector<unsigned char> encodeUrlSafe(std::vector<unsigned char> const& v);
std::vector<unsigned char> decodeUrlSafe(std::vector<unsigned char> const& v);

}}} // namespace cadmium::base::Base64

#endif // Netflix_Base_Base64_h_
