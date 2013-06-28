// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "Base32.h"
#include <limits>
#include <base/DebugUtil.h>

using namespace std;

namespace
{

// Copied from chromium's chrome_util.cc
string ByteArrayToBase32(const uint8_t* bytes, size_t size)
{
    static const char kEncoding[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    // Eliminate special cases first.
    if (size == 0)
    {
        return string();
    }
    else if (size == 1)
    {
        string ret;
        ret.push_back(kEncoding[(bytes[0] & 0xf8) >> 3]);
        ret.push_back(kEncoding[(bytes[0] & 0x07) << 2]);
        return ret;
    }
    else if (size >= numeric_limits<size_t>::max() / 8)
    {
        // If |size| is too big, the calculation of |encoded_length| below will
        // overflow.
        DLOG() << "Byte array is too long.\n";
        return string();
    }

    // Overestimate the number of bits in the string by 4 so that dividing by 5
    // is the equivalent of rounding up the actual number of bits divided by 5.
    const size_t encoded_length = (size * 8 + 4) / 5;

    string ret;
    ret.reserve(encoded_length);

    // A bit stream which will be read from the left and appended to from the
    // right as it's emptied.
    uint16_t bit_stream = (bytes[0] << 8) + bytes[1];
    size_t next_byte_index = 2;
    int free_bits = 0;
    while (free_bits < 16)
    {
        // Extract the 5 leftmost bits in the stream
        ret.push_back(kEncoding[(bit_stream & 0xf800) >> 11]);
        bit_stream <<= 5;
        free_bits += 5;

        // If there is enough room in the bit stream, inject another byte (if there
        // are any left...).
        if (free_bits >= 8 && next_byte_index < size)
        {
            free_bits -= 8;
            bit_stream += bytes[next_byte_index++] << free_bits;
        }
    }

    if (ret.length() != encoded_length)
    {
        DLOG() << "Base32::encode(): Encoding doesn't match expected length.\n";
        return string();
    }
    return ret;
}

}   // anonymous namespace

namespace cadmium { namespace Base32
{

string encode(vector<uint8_t>& in)
{
    return ByteArrayToBase32(&in[0], in.size());
}

}}  // namespace cadmium::Base32

