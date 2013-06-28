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
#ifndef Variant_h
#define Variant_h

#undef min
#undef max

#include <assert.h>
#include <map>
#include <sstream>
#include <string>
#include <vector>
#include <stdint.h>
#include <tr1/memory>

namespace cadmium { namespace base {

class Variant
{
public:
    class CustomData
    {
    public:
        CustomData(int t) : type(t) {}
        virtual ~CustomData() {}
        virtual std::string toString() const { return std::string(); }
        const int type;
    };
    enum Type {
        Null,
        String,
        Array,
        Map,
        Integer,
        Double,
        Boolean,
        Custom
    };

    Variant();
    Variant(const char *str);
    Variant(const std::string &str);
    Variant(const std::string &key, const Variant &value);
    Variant(const std::vector<Variant> &vec);
    Variant(const std::map<std::string, Variant> &map);
    Variant(const std::tr1::shared_ptr<CustomData> &custom);

    Variant(bool b);
    Variant(int val);
    Variant(long val);
    Variant(uint32_t val);
    Variant(double val);
    Variant(const Variant &other);
    ~Variant();

    template<typename T>
    Variant(const std::vector<T>& vec);

    template<typename A, typename B>
    Variant(const std::pair<A, B>& pair);

    template<typename T>
    Variant(const std::map<std::string, T>& map);

    static Variant fromJSON(const char *json);
    std::string toJSON(bool pretty=false) const;

    bool isNull() const;
    bool isString() const;
    bool isArray() const;
    bool isMap() const;
    inline bool isNumber() const { return isInteger() || isDouble(); }
    bool isInteger() const;
    bool isDouble() const;
    bool isBoolean() const;
    bool isCustom() const;

    template <typename T> T mapValue(const std::string &key, bool *okPtr = 0, const T &defaultValue = T()) const;
    template <typename T> T value(bool *ok = 0, const T &defaultValue = T()) const;
    template <typename T> static Variant::Type variantType();

    Variant convert(Type targetType) const;
    bool canConvert(Type targetType) const;
    Variant &operator=(const Variant &other);
    bool operator==(const Variant &other) const;
    bool operator!=(const Variant &other) const;
    void clear();
    Type type() const;

    bool boolean() const;
    int64_t integer() const;
    double dbl() const;
    std::tr1::shared_ptr<const CustomData> custom() const;
    std::string string() const;
    std::vector<Variant> array() const;
    std::map<std::string, Variant> map() const;

    inline Variant &operator[](const std::string &);
    inline const Variant operator[](const std::string &) const;
    inline Variant &operator[](int);
    inline const Variant operator[](int) const;
    inline bool contains(const std::string &key) const;
    inline void remove(const std::string &key);
    inline void remove(int);
    inline std::map<std::string, Variant>::const_iterator find(const std::string &name) const;
    inline std::map<std::string, Variant>::const_iterator begin() const;
    inline std::map<std::string, Variant>::const_iterator end() const;
    inline void push_back(const Variant &variant);
    inline int size() const;
    inline bool empty() const;

    Variant value(int idx) const { return operator[](idx); }
    Variant value(const std::string &key) const { return operator[](key); }

private:
    void convert(void *value) const;

    Type mType;
    union {
        std::string *stringPtr;
        std::vector<Variant> *arrayPtr;
        std::map<std::string, Variant> *mapPtr;
        int64_t integer;
        double dbl;
        bool boolean;
        std::tr1::shared_ptr<CustomData> *customPtr;
    } mData;
};

typedef std::map<std::string, Variant> VariantMap;
typedef std::vector<Variant> VariantArray;

inline Variant::Variant() : mType(Null)
{
}

inline Variant::Variant(const char *str) : mType(Null)
{
    if (str) {
        mType = String;
        mData.stringPtr = new std::string(str);
    }
}

inline Variant::Variant(const std::string &str)
{
    mType = String;
    mData.stringPtr = new std::string(str);
}

inline Variant::Variant(const std::string &key, const Variant &value)
{
    mType = Map;
    mData.mapPtr = new std::map<std::string, Variant>;
    (*mData.mapPtr)[key] = value;
}

inline Variant::Variant(const std::vector<Variant> &vec)
{
    mType = Array;
    mData.arrayPtr = new std::vector<Variant>(vec);
}

inline Variant::Variant(const std::map<std::string, Variant> &map)
{
    mType = Map;
    mData.mapPtr = new std::map<std::string, Variant>(map);
}

template<typename T>
inline Variant::Variant(const std::vector<T> &vec)
{
    mType = Array;
    mData.arrayPtr = new std::vector<Variant>;

    for (typename std::vector<T>::const_iterator it = vec.begin();
         it != vec.end(); ++it) {
        mData.arrayPtr->push_back(*it);
    }
}

template<typename A, typename B>
inline Variant::Variant(const std::pair<A, B> &pair)
{
    mType = Array;
    mData.arrayPtr = new std::vector<Variant>;

    mData.arrayPtr->push_back(pair.first);
    mData.arrayPtr->push_back(pair.second);
}

template<typename T>
inline Variant::Variant(const std::map<std::string, T> &map)
{
    mType = Map;
    mData.mapPtr = new std::map<std::string, Variant>;
    for (typename std::map<std::string, T>::const_iterator it = map.begin(); it != map.end(); ++it) {
        (*mData.mapPtr)[(*it).first] = Variant((*it).second);
    }
}

inline Variant::Variant(bool b)
{
    mType = Boolean;
    mData.boolean = b;
}

inline Variant::Variant(int val)
{
    mType = Integer;
    mData.integer = val;
}

inline Variant::Variant(long val)
{
    mType = Integer;
    mData.integer = val;
}

inline Variant::Variant(uint32_t val)
{
    mType = Integer;
    mData.integer = val;
}

inline Variant::Variant(double val)
{
    mType = Double;
    mData.dbl = val;
}

inline Variant::Variant(const std::tr1::shared_ptr<CustomData> &data)
    : mType(data.get() ? Custom : Null)
{
    if (data.get()) {
        mData.customPtr = new std::tr1::shared_ptr<CustomData>(data);
    }
}

inline Variant::Variant(const Variant &other)
    : mType(Null)
{
    operator=(other);
}

inline Variant::~Variant()
{
    clear();
}

inline void Variant::clear()
{
    switch (mType) {
    case Null:
    case Integer:
    case Boolean:
    case Double:
        break;
    case Array:
        delete mData.arrayPtr;
        break;
    case String:
        delete mData.stringPtr;
        break;
    case Map:
        delete mData.mapPtr;
        break;
    case Custom:
        delete mData.customPtr;
        break;
    }
    mType = Null;
}

inline bool Variant::isNull() const
{
    return mType == Null;
}

inline bool Variant::isString() const
{
    return mType == String;
}

inline bool Variant::isArray() const
{
    return mType == Array;
}

inline bool Variant::isMap() const
{
    return mType == Map;
}

inline bool Variant::isInteger() const
{
    return mType == Integer;
}

inline bool Variant::isDouble() const
{
    return mType == Double;
}

inline bool Variant::isBoolean() const
{
    return mType == Boolean;
}

inline bool Variant::isCustom() const
{
    return mType == Custom;
}

template <typename T> inline T Variant::mapValue(const std::string &key, bool *okPtr, const T &defaultValue) const
{
    if (type() == Map) {
        const std::map<std::string, Variant>::const_iterator it = mData.mapPtr->find(key);
        if (it != mData.mapPtr->end()) {
            bool ok;
            const T t = (*it).second.value<T>(&ok);
            if (okPtr)
                *okPtr = ok;
            if (ok)
                return t;
        } else if (okPtr) {
            *okPtr = false;
        }
    } else if (okPtr) {
        *okPtr = false;
    }
    return defaultValue;
}
template <typename T> inline T Variant::value(bool *ok, const T &defaultValue) const
{
    const Variant v = convert(variantType<T>());
    if (ok)
        *ok = !v.isNull();
    if (!v.isNull()) {
        T t;
        v.convert(&t);
        return t;
    }
    return defaultValue;
}

namespace VariantType {
template <typename T> static inline Variant::Type variantType(T *t) {
    invalidVariantType(t);
    return Variant::Null;
}
template <> inline Variant::Type variantType(int*) {
    return Variant::Integer;
}
template <> inline Variant::Type variantType(int64_t*) {
    return Variant::Integer;
}
template <> inline Variant::Type variantType(bool*) {
    return Variant::Boolean;
}
template <> inline Variant::Type variantType(double*) {
    return Variant::Double;
}
template <> inline Variant::Type variantType(std::vector<Variant>*) {
    return Variant::Array;
}
template <> inline Variant::Type variantType(std::map<std::string, Variant>*) {
    return Variant::Map;
}
template <> inline Variant::Type variantType(std::string*) {
    return Variant::String;
}
}

template <typename T> inline Variant::Type Variant::variantType()
{
    return VariantType::variantType<T>(static_cast<T*>(0));
}

inline Variant Variant::convert(Type targetType) const
{
    if (isNull())
        return Variant();
    if (targetType == mType)
        return *this;
    switch (targetType) {
    case Boolean:
        switch (mType) {
        case Null:
            return Variant(false);
        case Integer:
            return (integer() != 0);
        case Double:
            return (dbl() != 0);
        case Array:
        case Map:
        case Custom:
        case Boolean:
            break;
        case String: {
            if (*mData.stringPtr == "true")
                return Variant(true);
            if (*mData.stringPtr == "false")
                return Variant(false);
            const Variant val = convert(Double);
            if (val.type() == Double)
                return val.dbl();
            break;
        }
        }
        break;
    case Integer:
        switch (mType) {
        case Boolean:
            return (mData.boolean ? 1 : 0);
        case Null:
        case Array:
        case Map:
        case Custom:
        case Integer:
            break;
        case Double:
            return static_cast<int>(dbl());
        case String: {
            std::istringstream iss(*mData.stringPtr);
            int integer = 0;
            iss >> std::dec >> integer;
            if (!iss.fail()) {
                // Different versions of libstdc++ behaves differently when the
                // stream is positioned at the end of the string. With
                // libstdc++.so.6.0.16 (ubuntu 11.10) it returns -1, in previous
                // versions it would return string.size()
                const int pos = iss.tellg();
                if (pos == -1 || pos == static_cast<int>(mData.stringPtr->size()))
                    return Variant(integer);
            }
            break;
        }
        }
        break;
    case Double:
        switch (mType) {
        case Boolean:
            return (mData.boolean ? 1.0 : 0.0);
        case Double:
        case Null:
        case Array:
        case Map:
        case Custom:
            break;
        case Integer:
            return static_cast<double>(integer());
        case String: {
            std::istringstream iss(*mData.stringPtr);
            double dbl;
            iss >> std::dec >> dbl;
            if (!iss.fail()) {
                // Different versions of libstdc++ behaves differently when the
                // stream is positioned at the end of the string. With
                // libstdc++.so.6.0.16 (ubuntu 11.10) it returns -1, in previous
                // versions it would return string.size()
                const int pos = iss.tellg();
                if (pos == -1 || pos == static_cast<int>(mData.stringPtr->size()))
                    return Variant(dbl);
            }
            break;
        }
        }
        break;
    case String:
        return toJSON();
    case Map:
    case Array:
    case Null:
    case Custom:
        break;
    }
    return Variant();
}

inline bool Variant::canConvert(Type targetType) const
{
    if (targetType == mType || targetType == Null)
        return true;
    return !convert(targetType).isNull();
}

inline Variant &Variant::operator=(const Variant &other)
{
    clear();
    mType = other.mType;
    switch (mType) {
    case Custom:
        mData.customPtr = new std::tr1::shared_ptr<CustomData>(*other.mData.customPtr);
        break;
    case Null:
    case Boolean:
        mData.boolean = other.mData.boolean;
        break;
    case Integer:
        mData.integer = other.mData.integer;
        break;
    case Double:
        mData.dbl = other.mData.dbl;
        break;
    case Array:
        mData.arrayPtr = new std::vector<Variant>(*other.mData.arrayPtr);
        break;
    case Map:
        mData.mapPtr = new std::map<std::string, Variant>(*other.mData.mapPtr);
        break;
    case String:
        mData.stringPtr = new std::string(*other.mData.stringPtr);
        break;
    }
    return *this;
}

inline bool Variant::operator==(const Variant &other) const
{
    const Type me = type();
    const Type him = other.type();
    if (me == him) {
        switch (me) {
        case Custom:
            return false;
        case Null:
            return true;
        case Integer:
            return (mData.integer == other.mData.integer);
        case Boolean:
            return (mData.boolean == other.mData.boolean);
        case Double:
            return (mData.dbl == other.mData.dbl);
        case Array:
            return (*mData.arrayPtr == *other.mData.arrayPtr);
        case String:
            return (*mData.stringPtr == *other.mData.stringPtr);
        case Map:
            return (*mData.mapPtr == *other.mData.mapPtr);
        }
    }
    return false;
}

inline bool Variant::operator!=(const Variant &other) const
{
    return !operator==(other);
}

inline Variant::Type Variant::type() const
{
    return mType;
}

inline bool Variant::boolean() const
{
    return isBoolean() ? mData.boolean : false;
}

inline int64_t Variant::integer() const
{
    return isInteger() ? mData.integer : 0;
}

inline double Variant::dbl() const
{
    return isDouble() ? mData.dbl : .0;
}

inline std::string Variant::string() const
{
    return isString() ? *mData.stringPtr : std::string();
}

inline std::vector<Variant> Variant::array() const
{
    return isArray() ? *mData.arrayPtr : std::vector<Variant>();
}

inline std::map<std::string, Variant> Variant::map() const
{
    return isMap() ? *mData.mapPtr : std::map<std::string, Variant>();
}

inline std::tr1::shared_ptr<const Variant::CustomData> Variant::custom() const
{
    return isCustom() ? *mData.customPtr : std::tr1::shared_ptr<Variant::CustomData>();
}

inline void Variant::convert(void *value) const
{
    switch (type()) {
    case Null:
        break;
    case Custom: {
        std::tr1::shared_ptr<CustomData> *ptr = reinterpret_cast<std::tr1::shared_ptr<CustomData> *>(value);
        *ptr = *mData.customPtr;
        break; }
    case Integer: {
        int *ptr = reinterpret_cast<int*>(value);
        *ptr = mData.integer;
        break; }
    case Boolean: {
        bool *ptr = reinterpret_cast<bool*>(value);
        *ptr = mData.boolean;
        break; }
    case Double: {
        double *ptr = reinterpret_cast<double*>(value);
        *ptr = mData.dbl;
        break; }
    case Array: {
        std::vector<Variant> *ptr = reinterpret_cast<std::vector<Variant> *>(value);
        *ptr = *mData.arrayPtr;
        break; }
    case String: {
        std::string *ptr = reinterpret_cast<std::string*>(value);
        *ptr = *mData.stringPtr;
        break; }
    case Map: {
        std::map<std::string, Variant> *ptr = reinterpret_cast<std::map<std::string, Variant> *>(value);
        *ptr = *mData.mapPtr;
        break; }
    }
}

inline Variant &Variant::operator[](const std::string &key)
{
    switch (type()) {
    case Null:
        mType = Map;
        mData.mapPtr = new std::map<std::string, Variant>();
        break;
    case Map:
        break;
    default:
        assert(0);
        break;
    }
    return (*mData.mapPtr)[key];
}

inline const Variant Variant::operator[](const std::string &key) const
{
    if (isMap()) {
        const std::map<std::string, Variant>::const_iterator it = mData.mapPtr->find(key);
        if (it != mData.mapPtr->end())
            return (*it).second;
    }
    return Variant();
}

inline Variant &Variant::operator[](int idx)
{
    assert(idx >= 0);
    switch (type()) {
    case Null:
        mType = Array;
        mData.arrayPtr = new std::vector<Variant>();
        break;
    case Array:
        break;
    default:
        assert(0);
        break;
    }
    if (mData.arrayPtr->size() <= size_t(idx))
        mData.arrayPtr->resize(idx + 1);
    return (*mData.arrayPtr)[idx];
}

inline const Variant Variant::operator[](int idx) const
{
    assert(idx >= 0);
    if (isArray() && idx < size())
        return array()[idx];
    return Variant();
}

inline void Variant::push_back(const Variant &variant)
{
    operator[](size()) = variant;
}

inline bool Variant::contains(const std::string &key) const
{
    return isMap() ? mData.mapPtr->find(key) != mData.mapPtr->end() : false;
}

inline void Variant::remove(const std::string &key)
{
    if (isMap())
        mData.mapPtr->erase(key);
}

inline void Variant::remove(int index)
{
    if (!isArray())
        return;

    mData.arrayPtr->erase(mData.arrayPtr->begin() + index);
}

inline std::map<std::string, Variant>::const_iterator Variant::find(const std::string &name) const
{
    return isMap() ? mData.mapPtr->find(name) : std::map<std::string, Variant>::const_iterator();
}

inline std::map<std::string, Variant>::const_iterator Variant::begin() const
{
    return isMap() ? mData.mapPtr->begin() : std::map<std::string, Variant>::const_iterator();
}

inline std::map<std::string, Variant>::const_iterator Variant::end() const
{
    return isMap() ? mData.mapPtr->end() : std::map<std::string, Variant>::const_iterator();
}

inline int Variant::size() const
{
    switch (type()) {
    case Map:
        return mData.mapPtr->size();
    case Array:
        return mData.arrayPtr->size();
    default:
        break;
    }
    return 0;
}

inline bool Variant::empty() const
{
    return !size();
}

}}  // namespace cadmium::base

#endif
