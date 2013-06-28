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
#include "Variant.h"
#include <string.h>
#include <cJSON.h>
#include "JSONFormatter.h"


using namespace cadmium::base;

static inline Variant fromJSON(const cJSON *cjson)
{
    assert(cjson);
    switch (cjson->type) {
    case cJSON_False: return Variant(false);
    case cJSON_True: return Variant(true);
    case cJSON_NULL: return Variant();
    case cJSON_Number: return (cjson->valuedouble == cjson->valueint
                               ? Variant(cjson->valueint)
                               : Variant(cjson->valuedouble));
    case cJSON_String: return Variant(cjson->valuestring);
    case cJSON_Array: {
        VariantArray list;
        for (cjson=cjson->child; cjson; cjson = cjson->next)
            list.push_back(fromJSON(cjson));
        return list; }
    case cJSON_Object: {
        VariantMap map;
        for (cjson=cjson->child; cjson; cjson = cjson->next)
            map[cjson->string] = fromJSON(cjson);
        return map; }
    default:
        assert(0);
        break;
    }
    return VariantMap();
}

Variant Variant::fromJSON(const char *json)
{
    if (!json || !*json)
        return Variant();

    cJSON* cjson = cJSON_Parse(json);
    if (!cjson) {
        //Log::error(TRACE_VARIANT, "Can't parse JSON [%s]", json);
        //assert(false);
        return VariantMap();
    }
    const Variant ret = ::fromJSON(cjson);
    cJSON_Delete(cjson);
    return ret;
}

std::string Variant::toJSON(bool pretty) const
{
    if (isString())
        return string();

    uint32_t flags = JSONFormatter::None;
    if(pretty)
        flags |= JSONFormatter::Pretty;
    JSONFormatter formatter(flags);
    return formatter.format(*this);
}
