/*
 * (c) 2011 Netflix, Inc.  All content herein is protected by
 * U.S. copyright and other applicable intellectual property laws and
 * may not be copied without the express permission of Netflix, Inc.,
 * which reserves all rights.  Reuse of any of this content for any
 * purpose without the permission of Netflix, Inc. is strictly
 * prohibited.
 */
#ifndef BASE32_H_
#define BASE32_H_

#include <string>
#include <vector>
#include <stdint.h>

namespace cadmium { namespace Base32 {

std::string encode(std::vector<uint8_t> &in);

}} // namespace

#endif /* BASE32_H_ */
