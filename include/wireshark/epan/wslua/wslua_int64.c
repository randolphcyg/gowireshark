/*
 * A Lua userdata object for 64-bit signed/unsigned integers.
 *
 * I, Hadriel Kaplan, the author of wslua_int6464.c, wish to put it in
 * the Public Domain.  That is not universally accepted, however,
 * so you may license it under the FreeBSD License instead, which is an open
 * source license approved for GPL use as well as commercial etc.
 * It's even less restrictive than the MIT license, because it requires
 * no attribution anywhere - I don't *want* attribution.

Copyright (C) 2013 Hadriel Kaplan <hadrielk@yahoo.com>
All rights reserved.

SPDX-License-Identifier: BSD-2-Clause

The views and conclusions contained in the software and documentation are those
of the authors and should not be interpreted as representing official policies,
either expressed or implied, of the FreeBSD Project.
*/

#include "config.h"

#include "wslua.h"

    /*
    WSLUA_MODULE Int64 Handling 64-bit Integers

    Lua uses one single number representation, which is chosen at compile time, and since it is often set to IEEE 754 double precision floating point, one cannot store 64 bit integers with full precision.

    Lua numbers are stored as floating point (doubles) internally, not integers; thus while they can represent incredibly large numbers, above 2^53 they lose integral precision -- they can't represent every whole integer value.
    For example if you set a lua variable to the number 9007199254740992 and tried to increment it by 1, you'd get the same number because it can't represent 9007199254740993 (only the even number 9007199254740994).

    Therefore, in order to count higher than 2^53 in integers, we need a true integer type.
    The way this is done is with an explicit 'Int64' or 'UInt64' object (i.e., Lua userdata).
    This object has metamethods for all of the math and comparison operators, so you can handle it like any number variable.
    For the math operators, it can even be mixed with plain Lua numbers.

    For example 'my64num = my64num + 1' will work even if 'my64num' is a <<lua_class_Int64,`Int64`>> or <<lua_class_UInt64,`UInt64`>> object.
    Note that comparison operators ('==','$$<=$$','>', etc.) will not work with plain numbers -- only other Int64/UInt64 objects.
    This is a limitation of Lua itself, in terms of how it handles operator overloading.

    [WARNING]
    ====
    Many of the UInt64/Int64 functions accept a Lua number as an argument.
    You should be very careful to never use Lua numbers bigger than 32 bits (i.e., the number value 4,294,967,295 or the literal 0xFFFFFFFF) for such arguments, because Lua itself does not handle bigger numbers consistently across platforms (32-bit vs. 64-bit systems), and because a Lua number is a C-code double which cannot have more than 53 bits of precision.
    Instead, use a Int64 or UInt64 for the argument.
    ====

    For example, do this...

    [source,lua]
    ----
    local mynum = UInt64(0x2b89dd1e, 0x3f91df0b)
    ----

    ...instead of this:

    [source,lua]
    ----
    -- Bad. Leads to inconsistent results across platforms
    local mynum = UInt64(0x3f91df0b2b89dd1e)
    ----

    And do this...

    [source,lua]
    ----
    local masked = mynum:band(UInt64(0, 0xFFFFFFFF))
    ----

    ...instead of this:

    [source,lua]
    ----
    -- Bad. Leads to inconsistent results across platforms
    local masked = mynum:band(0xFFFFFFFF00000000)
    ----

    [NOTE]
    ====
    Lua 5.3 and later adds a second number representation for integers, which is also chosen at compile time. It is usually a 64-bit signed integer type, even on 32-bit platforms.
    (Lua 5.2 and earlier have an integer type, but this is not used for storing numbers, only for casting, and on 32-bit platforms is 32-bits wide.)
    Wireshark 4.4 and later will use the Lua integer type where possible, but as storing
    64-bit unsigned integers in a Lua Integer can result in signed number overflow, `UInt64`
    is still necessary. `Int64` is also still available for use.
    ====

    */

#define LUATYPE64_STRING_SIZE 21  /* string to hold 18446744073709551615 */

#if G_BYTE_ORDER == G_LITTLE_ENDIAN
#define IS_LITTLE_ENDIAN true
#else
#define IS_LITTLE_ENDIAN false
#endif

WSLUA_CLASS_DEFINE_BASE(Int64,NOP,0);
    /*
    <<lua_class_Int64,`Int64`>> represents a 64 bit signed integer.

    Note the caveats <<lua_module_Int64,listed above>>.
    */

/* A checkInt64 but that also auto-converts numbers, strings, and UINT64 to a int64_t */
static int64_t getInt64(lua_State *L, int i)
{
    char *end = NULL;
    (void) end;
    switch (lua_type(L,i))
    {
        case LUA_TNUMBER:
            return wslua_checkint64(L,i);
        case LUA_TSTRING:
            return g_ascii_strtoll(luaL_checkstring(L,i),&end,10);
        case LUA_TUSERDATA:
            if (isUInt64(L, i)) {
                return (Int64) toUInt64(L, i);
            }
            /* fall through */
        default:
            return checkInt64(L,i);
        }
}


/* Encodes Int64 userdata into Lua string struct with given endianness */
void Int64_pack(lua_State* L, luaL_Buffer *b, int idx, bool asLittleEndian) {
    int64_t value = checkInt64(L,idx);
    int8_t buff[sizeof(int64_t)];

    if (asLittleEndian) {
        unsigned i;
        for (i = 0; i < sizeof(int64_t); i++) {
            buff[i] = (value & 0xff);
            value >>= 8;
        }
    }
    else {
        int i;
        for (i = sizeof(int64_t) - 1; i >= 0; i--) {
            buff[i] = (value & 0xff);
            value >>= 8;
        }
    }
    luaL_addlstring(b, (char*)buff, sizeof(int64_t));
}

WSLUA_METHOD Int64_encode(lua_State* L) {
    /* Encodes the <<lua_class_Int64,`Int64`>> number into an 8-byte Lua string using the given endianness. */
#define WSLUA_OPTARG_Int64_encode_ENDIAN 2 /* If set to true then little-endian is used,
                                              if false then big-endian; if missing or `nil`,
                                              native host endian. */
    luaL_Buffer b;
    bool asLittleEndian = IS_LITTLE_ENDIAN;

    if (lua_gettop(L) >= WSLUA_OPTARG_Int64_encode_ENDIAN) {
        if (lua_type(L,WSLUA_OPTARG_Int64_encode_ENDIAN) == LUA_TBOOLEAN)
            asLittleEndian = lua_toboolean(L,WSLUA_OPTARG_Int64_encode_ENDIAN);
    }

    luaL_buffinit(L, &b);

    Int64_pack(L, &b, 1, asLittleEndian);

    luaL_pushresult(&b);
    WSLUA_RETURN(1); /* The Lua string. */
}

/* Decodes from string buffer struct into Int64 userdata, with given endianness */
int Int64_unpack(lua_State* L, const char *buff, bool asLittleEndian) {
    int64_t value = 0;
    int i;

    if (asLittleEndian) {
        for (i = sizeof(int64_t) - 1; i >= 0; i--) {
            value <<= 8;
            value |= (int64_t)(unsigned char)buff[i];
        }
    }
    else {
        for (i = 0; i < (int) sizeof(int64_t); i++) {
            value <<= 8;
            value |= (int64_t)(unsigned char)buff[i];
        }
    }

    pushInt64(L,value);
    return 1;
}

WSLUA_CONSTRUCTOR Int64_decode(lua_State* L) {
    /* Decodes an 8-byte Lua string, using the given endianness, into a new <<lua_class_Int64,`Int64`>> object. */
#define WSLUA_ARG_Int64_decode_STRING 1 /* The Lua string containing a binary 64-bit integer. */
#define WSLUA_OPTARG_Int64_decode_ENDIAN 2 /* If set to true then little-endian is used,
                                              if false then big-endian; if missing or `nil`, native
                                              host endian. */
    bool asLittleEndian = IS_LITTLE_ENDIAN;
    size_t len = 0;
    const char *s = luaL_checklstring(L, WSLUA_ARG_Int64_decode_STRING, &len);

    if (lua_gettop(L) >= WSLUA_OPTARG_Int64_decode_ENDIAN) {
        if (lua_type(L,WSLUA_OPTARG_Int64_decode_ENDIAN) == LUA_TBOOLEAN)
            asLittleEndian = lua_toboolean(L,WSLUA_OPTARG_Int64_decode_ENDIAN);
    }

    if (len == sizeof(int64_t)) {
        Int64_unpack(L, s, asLittleEndian);
    } else {
        lua_pushnil(L);
    }

    WSLUA_RETURN(1); /* The <<lua_class_Int64,`Int64`>> object created, or nil on failure. */
}

WSLUA_CONSTRUCTOR Int64_new(lua_State* L) {
    /* Creates a <<lua_class_Int64,`Int64`>> object. */
#define WSLUA_OPTARG_Int64_new_VALUE 1 /* A number, <<lua_class_UInt64,`UInt64`>>, <<lua_class_Int64,`Int64`>>, or string of ASCII digits
                                          to assign the value of the new <<lua_class_Int64,`Int64`>>. Default is 0. */
#define WSLUA_OPTARG_Int64_new_HIGHVALUE 2 /* If this is a number and the first argument was
                                              a number, then the first will be treated as a
                                              lower 32 bits, and this is the high-order 32
                                              bit number. */
    int64_t value = 0;

    if (lua_gettop(L) >= 1) {
        switch(lua_type(L, WSLUA_OPTARG_Int64_new_VALUE)) {
            case LUA_TNUMBER:
                value = wslua_toint64(L, WSLUA_OPTARG_Int64_new_VALUE);
                if (lua_gettop(L) == 2 &&
                    lua_type(L, WSLUA_OPTARG_Int64_new_HIGHVALUE) == LUA_TNUMBER) {
                    int64_t h = wslua_toint64(L, WSLUA_OPTARG_Int64_new_HIGHVALUE);
                    value &= UINT64_C(0x00000000FFFFFFFF);
                    h <<= 32; h &= UINT64_C(0xFFFFFFFF00000000);
                    value += h;
                }
                break;
            case LUA_TSTRING:
            case LUA_TUSERDATA:
                value = getInt64(L,WSLUA_OPTARG_Int64_new_VALUE);
                break;
            default:
                WSLUA_OPTARG_ERROR(Int64_new,VALUE,"must be a number, UInt64, Int64, or string");
                break;
        }
    }

    pushInt64(L,value);

    WSLUA_RETURN(1); /* The new <<lua_class_Int64,`Int64`>> object. */
}

WSLUA_METAMETHOD Int64__call(lua_State* L) {
    /* Creates a <<lua_class_Int64,`Int64`>> object. */
    lua_remove(L,1); /* remove the table */
    WSLUA_RETURN(Int64_new(L)); /* The new <<lua_class_Int64,`Int64`>> object. */
}

WSLUA_CONSTRUCTOR Int64_max(lua_State* L) {
    /* Creates an <<lua_class_Int64,`Int64`>> of the maximum possible positive value. In other words, this should return an Int64 object of the number 9,223,372,036,854,775,807. */
    pushInt64(L, INT64_MAX);
    WSLUA_RETURN(1); /* The new <<lua_class_Int64,`Int64`>> object of the maximum value. */
}

WSLUA_CONSTRUCTOR Int64_min(lua_State* L) {
    /* Creates an <<lua_class_Int64,`Int64`>> of the minimum possible negative value. In other words, this should return an Int64 object of the number -9,223,372,036,854,775,808. */
    pushInt64(L, INT64_MIN);
    WSLUA_RETURN(1); /* The new <<lua_class_Int64,`Int64`>> object of the minimum value. */
}


WSLUA_METHOD Int64_tonumber(lua_State* L) {
    /* Returns a Lua number of the <<lua_class_Int64,`Int64`>> value. Note that this may lose precision. */
    lua_pushnumber(L, (lua_Number)(checkInt64(L,1)));
    WSLUA_RETURN(1); /* The Lua number. */
}

WSLUA_CONSTRUCTOR Int64_fromhex(lua_State* L) {
    /* Creates an <<lua_class_Int64,`Int64`>> object from the given hexadecimal string. */
#define WSLUA_ARG_Int64_fromhex_HEX 1 /* The hex-ASCII Lua string. */
    uint64_t result = 0;
    size_t len = 0;
    const char *s = luaL_checklstring(L,WSLUA_ARG_Int64_fromhex_HEX,&len);

    if (len > 0) {
        if (sscanf(s, "%" SCNx64, &result) != 1) {
            return luaL_error(L, "Error decoding the passed-in hex string");
        }
    }
    pushInt64(L,(int64_t)result);
    WSLUA_RETURN(1); /* The new <<lua_class_Int64,`Int64`>> object. */
}

WSLUA_METHOD Int64_tohex(lua_State* L) {
    /* Returns a hexadecimal string of the <<lua_class_Int64,`Int64`>> value. */
#define WSLUA_OPTARG_Int64_tohex_NUMBYTES 2 /* The number of hex chars/nibbles to generate.
                                             A negative value generates uppercase. Default is 16. */
    int64_t b = getInt64(L,1);
    lua_Integer n = luaL_optinteger(L, WSLUA_OPTARG_Int64_tohex_NUMBYTES, 16);
    const char *hexdigits = "0123456789abcdef";
    char buf[16];
    lua_Integer i;
    if (n < 0) { n = -n; hexdigits = "0123456789ABCDEF"; }
    if (n > 16) n = 16;
    for (i = n-1; i >= 0; --i) { buf[i] = hexdigits[b & 15]; b >>= 4; }
    lua_pushlstring(L, buf, (size_t)n);
    WSLUA_RETURN(1); /* The string hex. */
}

WSLUA_METHOD Int64_higher(lua_State* L) {
    /* Returns a Lua number of the higher 32 bits of the <<lua_class_Int64,`Int64`>> value. A negative <<lua_class_Int64,`Int64`>>
       will return a negative Lua number.
     */
    int64_t num = getInt64(L,1);
    int64_t b = num;
    lua_Number n = 0;
    if (b < 0) b = -b; /* masking/shifting negative int64 isn't working on some platforms */
    b &= UINT64_C(0x7FFFFFFF00000000);
    b >>= 32;
    n = (lua_Number)(uint32_t)(b & UINT64_C(0x00000000FFFFFFFFF));
    if (num < 0) n = -n;
    lua_pushnumber(L,n);
    WSLUA_RETURN(1); /* The Lua number. */
}

WSLUA_METHOD Int64_lower(lua_State* L) {
    /* Returns a Lua number of the lower 32 bits of the <<lua_class_Int64,`Int64`>> value. This will always be positive. */
    int64_t b = getInt64(L,1);
    if (b < 0) b = -b; /* masking/shifting negative int64 isn't working on some platforms */
    lua_pushnumber(L,(uint32_t)(b & UINT64_C(0x00000000FFFFFFFFF)));
    WSLUA_RETURN(1); /* The Lua number. */
}

WSLUA_METAMETHOD Int64__tostring(lua_State* L) {
    /* Converts the <<lua_class_Int64,`Int64`>> into a string of decimal digits. */
    int64_t num = getInt64(L,1);
    char s[LUATYPE64_STRING_SIZE];
    if (snprintf(s, LUATYPE64_STRING_SIZE, "%" PRId64, num) < 0) {
        return luaL_error(L, "Error writing Int64 to a string");
    }
    lua_pushstring(L,s);
    WSLUA_RETURN(1); /* The Lua string. */
}

WSLUA_METAMETHOD Int64__unm(lua_State* L) {
    /* Returns the negative of the <<lua_class_Int64,`Int64`>> as a new <<lua_class_Int64,`Int64`>>. */
    pushInt64(L,-(getInt64(L,1)));
    WSLUA_RETURN(1); /* The new <<lua_class_Int64,`Int64`>>. */
}

#define WSLUA_MATH_OP_FUNC(obj,op) \
    /* use the 'get' form so we can accept numbers as well */ \
    obj num1 = get##obj(L,1); \
    obj num2 = get##obj(L,2); \
    push##obj(L,(num1) op (num2)); \
    return 1

WSLUA_METAMETHOD Int64__add(lua_State* L) {
    /* Adds two <<lua_class_Int64,`Int64`>> together and returns a new one. The value may wrapped. */
    WSLUA_MATH_OP_FUNC(Int64,+);
}

WSLUA_METAMETHOD Int64__sub(lua_State* L) {
    /* Subtracts two <<lua_class_Int64,`Int64`>> and returns a new one. The value may wrapped. */
    WSLUA_MATH_OP_FUNC(Int64,-);
}

WSLUA_METAMETHOD Int64__mul(lua_State* L) {
    /* Multiplies two <<lua_class_Int64,`Int64`>> and returns a new one. The value may truncated. */
    WSLUA_MATH_OP_FUNC(Int64,*);
}

WSLUA_METAMETHOD Int64__div(lua_State* L) {
    /* Divides two <<lua_class_Int64,`Int64`>> and returns a new one. Integer divide, no remainder.
       Trying to divide by zero results in a Lua error.
     */
    Int64 num1 = getInt64(L,1);
    Int64 num2 = getInt64(L,2);
    if (num2 == 0) {
        return luaL_error(L, "Trying to divide Int64 by zero");
    }
    pushInt64(L, num1 / num2);
    WSLUA_RETURN(1); /* The <<lua_class_Int64,`Int64`>> object. */
}

WSLUA_METAMETHOD Int64__mod(lua_State* L) {
    /* Divides two <<lua_class_Int64,`Int64`>> and returns a new one of the remainder.
       Trying to modulo by zero results in a Lua error.
     */
    Int64 num1 = getInt64(L,1);
    Int64 num2 = getInt64(L,2);
    if (num2 == 0) {
        return luaL_error(L, "Trying to modulo Int64 by zero");
    }
    pushInt64(L, num1 % num2);
    WSLUA_RETURN(1); /* The <<lua_class_Int64,`Int64`>> object. */
}

WSLUA_METAMETHOD Int64__pow(lua_State* L) {
    /* The first <<lua_class_Int64,`Int64`>> is taken to the power of the second <<lua_class_Int64,`Int64`>>, returning a new
       one. This may truncate the value.
     */
    int64_t num1 = getInt64(L,1);
    int64_t num2 = getInt64(L,2);
    int64_t result;
    if (num1 == 2) {
        result = (num2 >= 8 * (int64_t) sizeof(int64_t)) ? 0 : ((int64_t)1 << num2);
    }
    else {
        for (result = 1; num2 > 0; num2 >>= 1) {
            if (num2 & 1) result *= num1;
            num1 *= num1;
        }
    }
    pushInt64(L,result);
    WSLUA_RETURN(1); /* The <<lua_class_Int64,`Int64`>> object. */
}

#define WSLUA_COMP_OP_FUNC(obj,op) \
    obj num1 = get##obj(L,1); \
    obj num2 = get##obj(L,2); \
    lua_pushboolean(L,(num1) op (num2)); \
    return 1

WSLUA_METAMETHOD Int64__eq(lua_State* L) {
    /* Returns `true` if both <<lua_class_Int64,`Int64`>> are equal. */
    WSLUA_COMP_OP_FUNC(Int64,==);
}

WSLUA_METAMETHOD Int64__lt(lua_State* L) {
    /* Returns `true` if first <<lua_class_Int64,`Int64`>> is less than the second. */
    WSLUA_COMP_OP_FUNC(Int64,<);
}

WSLUA_METAMETHOD Int64__le(lua_State* L) {
    /* Returns `true` if the first <<lua_class_Int64,`Int64`>> is less than or equal to the second. */
    WSLUA_COMP_OP_FUNC(Int64,<=);
}

WSLUA_METHOD Int64_bnot(lua_State* L) {
    /* Returns a <<lua_class_Int64,`Int64`>> of the bitwise 'not' operation. */
    pushInt64(L,~(getInt64(L,1)));
    WSLUA_RETURN(1); /* The <<lua_class_Int64,`Int64`>> object. */
}

#define WSLUA_BIT_OP_FUNC(obj,op) \
    int32_t i; \
    obj num = get##obj(L,1); \
    for (i = lua_gettop(L); i > 1; i--) { \
        num op get##obj(L,i); \
    } \
    push##obj(L,num); \
    return 1

WSLUA_METHOD Int64_band(lua_State* L) {
    /* Returns a <<lua_class_Int64,`Int64`>> of the bitwise 'and' operation with the given number/`Int64`/`UInt64`.
       Note that multiple arguments are allowed.
     */
    WSLUA_BIT_OP_FUNC(Int64,&=);
}

WSLUA_METHOD Int64_bor(lua_State* L) {
    /* Returns a <<lua_class_Int64,`Int64`>> of the bitwise 'or' operation, with the given number/`Int64`/`UInt64`.
       Note that multiple arguments are allowed.
     */
    WSLUA_BIT_OP_FUNC(Int64,|=);
}

WSLUA_METHOD Int64_bxor(lua_State* L) {
    /* Returns a <<lua_class_Int64,`Int64`>> of the bitwise 'xor' operation, with the given number/`Int64`/`UInt64`.
       Note that multiple arguments are allowed.
     */
    WSLUA_BIT_OP_FUNC(Int64,^=);
}

WSLUA_METHOD Int64_lshift(lua_State* L) {
    /* Returns a <<lua_class_Int64,`Int64`>> of the bitwise logical left-shift operation, by the given
       number of bits.
     */
#define WSLUA_ARG_Int64_lshift_NUMBITS 2 /* The number of bits to left-shift by. */
    uint64_t b = (uint64_t) getInt64(L,1);
    uint32_t n = wslua_checkuint32(L,WSLUA_ARG_Int64_lshift_NUMBITS);
    pushInt64(L,(int64_t)(b << n));
    WSLUA_RETURN(1); /* The <<lua_class_Int64,`Int64`>> object. */
}

WSLUA_METHOD Int64_rshift(lua_State* L) {
    /* Returns a <<lua_class_Int64,`Int64`>> of the bitwise logical right-shift operation, by the
       given number of bits.
     */
#define WSLUA_ARG_Int64_rshift_NUMBITS 2 /* The number of bits to right-shift by. */
    uint64_t b = (uint64_t) getInt64(L,1);
    uint32_t n = wslua_checkuint32(L,WSLUA_ARG_Int64_rshift_NUMBITS);
    pushInt64(L,(int64_t)(b >> n));
    WSLUA_RETURN(1); /* The <<lua_class_Int64,`Int64`>> object. */
}

WSLUA_METHOD Int64_arshift(lua_State* L) {
    /* Returns a <<lua_class_Int64,`Int64`>> of the bitwise arithmetic right-shift operation, by the
       given number of bits.
     */
#define WSLUA_ARG_Int64_arshift_NUMBITS 2 /* The number of bits to right-shift by. */
    int64_t b = getInt64(L,1);
    int32_t n = wslua_checkint32(L,WSLUA_ARG_Int64_arshift_NUMBITS);
    pushInt64(L,(b >> n));
    WSLUA_RETURN(1); /* The <<lua_class_Int64,`Int64`>> object. */
}

WSLUA_METHOD Int64_rol(lua_State* L) {
    /* Returns a <<lua_class_Int64,`Int64`>> of the bitwise left rotation operation, by the given number of
       bits (up to 63).
     */
#define WSLUA_ARG_Int64_rol_NUMBITS 2 /* The number of bits to roll left by. */
    uint64_t b = (uint64_t) getInt64(L,1);
    uint32_t n = wslua_checkuint32(L,WSLUA_ARG_Int64_rol_NUMBITS);
    pushInt64(L,(int64_t)((b << n) | (b >> (64-n))));
    WSLUA_RETURN(1); /* The <<lua_class_Int64,`Int64`>> object. */
}

WSLUA_METHOD Int64_ror(lua_State* L) {
    /* Returns a <<lua_class_Int64,`Int64`>> of the bitwise right rotation operation, by the given number of
       bits (up to 63).
     */
#define WSLUA_ARG_Int64_ror_NUMBITS 2 /* The number of bits to roll right by. */
    uint64_t b = (uint64_t) getInt64(L,1);
    uint32_t n = wslua_checkuint32(L,WSLUA_ARG_Int64_ror_NUMBITS);
    pushInt64(L,(int64_t)((b << (64-n)) | (b >> n)));
    WSLUA_RETURN(1); /* The <<lua_class_Int64,`Int64`>> object. */
}

WSLUA_METHOD Int64_bswap(lua_State* L) {
    /* Returns a <<lua_class_Int64,`Int64`>> of the bytes swapped. This can be used to convert little-endian
       64-bit numbers to big-endian 64 bit numbers or vice versa.
     */
    uint64_t b = (uint64_t) getInt64(L,1);
    uint64_t result = 0;
    size_t i;
    for (i = 0; i < sizeof(int64_t); i++) {
        result <<= 8;
        result |= (b & UINT64_C(0x00000000000000FF));
        b >>= 8;
    }
    pushInt64(L,(int64_t)result);
    WSLUA_RETURN(1); /* The <<lua_class_Int64,`Int64`>> object. */
}

/* Gets registered as metamethod automatically by WSLUA_REGISTER_CLASS/META. */
static int Int64__gc(lua_State* L _U_) {
    return 0;
}

WSLUA_METHODS Int64_methods[] = {
    WSLUA_CLASS_FNREG(Int64,new),
    WSLUA_CLASS_FNREG(Int64,max),
    WSLUA_CLASS_FNREG(Int64,min),
    WSLUA_CLASS_FNREG(Int64,tonumber),
    WSLUA_CLASS_FNREG(Int64,fromhex),
    WSLUA_CLASS_FNREG(Int64,tohex),
    WSLUA_CLASS_FNREG(Int64,higher),
    WSLUA_CLASS_FNREG(Int64,lower),
    WSLUA_CLASS_FNREG(Int64,encode),
    WSLUA_CLASS_FNREG(Int64,decode),
    WSLUA_CLASS_FNREG(Int64,bnot),
    WSLUA_CLASS_FNREG(Int64,band),
    WSLUA_CLASS_FNREG(Int64,bor),
    WSLUA_CLASS_FNREG(Int64,bxor),
    WSLUA_CLASS_FNREG(Int64,lshift),
    WSLUA_CLASS_FNREG(Int64,rshift),
    WSLUA_CLASS_FNREG(Int64,arshift),
    WSLUA_CLASS_FNREG(Int64,rol),
    WSLUA_CLASS_FNREG(Int64,ror),
    WSLUA_CLASS_FNREG(Int64,bswap),
    { NULL, NULL }
};

WSLUA_META Int64_meta[] = {
    WSLUA_CLASS_MTREG(Int64,tostring),
    WSLUA_CLASS_MTREG(Int64,call),
    WSLUA_CLASS_MTREG(wslua,concat),
    WSLUA_CLASS_MTREG(Int64,unm),
    WSLUA_CLASS_MTREG(Int64,add),
    WSLUA_CLASS_MTREG(Int64,sub),
    WSLUA_CLASS_MTREG(Int64,mul),
    WSLUA_CLASS_MTREG(Int64,div),
    WSLUA_CLASS_MTREG(Int64,mod),
    WSLUA_CLASS_MTREG(Int64,pow),
    WSLUA_CLASS_MTREG(Int64,eq),
    WSLUA_CLASS_MTREG(Int64,lt),
    WSLUA_CLASS_MTREG(Int64,le),
    { NULL, NULL }
};

LUALIB_API int Int64_register(lua_State* L) {
    WSLUA_REGISTER_CLASS(Int64);
    return 0;
}



WSLUA_CLASS_DEFINE_BASE(UInt64,NOP,0);
    /*
    <<lua_class_UInt64,`UInt64`>> represents a 64 bit unsigned integer, similar to <<lua_class_Int64,`Int64`>>.

    Note the caveats <<lua_module_Int64,listed above>>.
    */

/* A checkUInt64 but that also auto-converts numbers, strings, and <<lua_class_Int64,`Int64`>> to a uint64_t. */
uint64_t getUInt64(lua_State *L, int i)
{
    char *end = NULL;
    (void) end;
    switch (lua_type(L,i))
    {
        case LUA_TNUMBER:
            return wslua_checkuint64(L,i);
        case LUA_TSTRING:
            return g_ascii_strtoull(luaL_checkstring(L,i), &end, 0);
        case LUA_TUSERDATA:
            if (isInt64(L, i)) {
                return (UInt64) toInt64(L, i);
            }
            /* fall through */
        default:
            return checkUInt64(L,i);
        }
}

/* Encodes <<lua_class_UInt64,`UInt64`>> userdata into Lua string struct with given endianness */
void UInt64_pack(lua_State* L, luaL_Buffer *b, int idx, bool asLittleEndian) {
    uint64_t value = checkUInt64(L,idx);
    int8_t buff[sizeof(uint64_t)];

    if (asLittleEndian) {
        unsigned i;
        for (i = 0; i < sizeof(uint64_t); i++) {
            buff[i] = (value & 0xff);
            value >>= 8;
        }
    }
    else {
        int i;
        for (i = sizeof(uint64_t) - 1; i >= 0; i--) {
            buff[i] = (value & 0xff);
            value >>= 8;
        }
    }
    luaL_addlstring(b, (char*)buff, sizeof(uint64_t));
}

WSLUA_METHOD UInt64_encode(lua_State* L) {
    /* Encodes the <<lua_class_UInt64,`UInt64`>> number into an 8-byte Lua binary string, using given endianness. */
#define WSLUA_OPTARG_UInt64_encode_ENDIAN 2 /* If set to true then little-endian is used,
                                               if false then big-endian; if missing or `nil`,
                                               native host endian. */
    luaL_Buffer b;
    bool asLittleEndian = IS_LITTLE_ENDIAN;

    if (lua_gettop(L) >= 2) {
        if (lua_type(L,2) == LUA_TBOOLEAN)
            asLittleEndian = lua_toboolean(L,2);
    }

    luaL_buffinit(L, &b);

    UInt64_pack(L, &b, 1, asLittleEndian);

    luaL_pushresult(&b);
    WSLUA_RETURN(1); /* The Lua binary string. */
}

/* Decodes from string buffer struct into <<lua_class_UInt64,`UInt64`>> userdata, with given endianness. */
int UInt64_unpack(lua_State* L, const char *buff, bool asLittleEndian) {
    uint64_t value = 0;
    int i;

    if (asLittleEndian) {
        for (i = sizeof(uint64_t) - 1; i >= 0; i--) {
            value <<= 8;
            value |= (uint64_t)(unsigned char)buff[i];
        }
    }
    else {
        for (i = 0; i < (int) sizeof(uint64_t); i++) {
            value <<= 8;
            value |= (uint64_t)(unsigned char)buff[i];
        }
    }

    pushUInt64(L,value);
    return 1;
}

WSLUA_CONSTRUCTOR UInt64_decode(lua_State* L) {
    /* Decodes an 8-byte Lua binary string, using given endianness, into a new <<lua_class_UInt64,`UInt64`>> object. */
#define WSLUA_ARG_UInt64_decode_STRING 1 /* The Lua string containing a binary 64-bit integer. */
#define WSLUA_OPTARG_UInt64_decode_ENDIAN 2 /* If set to true then little-endian is used,
                                               if false then big-endian; if missing or `nil`,
                                               native host endian. */
    bool asLittleEndian = IS_LITTLE_ENDIAN;
    size_t len = 0;
    const char *s = luaL_checklstring(L, WSLUA_ARG_UInt64_decode_STRING, &len);

    if (lua_gettop(L) >= WSLUA_OPTARG_UInt64_decode_ENDIAN) {
        if (lua_type(L,WSLUA_OPTARG_UInt64_decode_ENDIAN) == LUA_TBOOLEAN)
            asLittleEndian = lua_toboolean(L,WSLUA_OPTARG_UInt64_decode_ENDIAN);
    }

    if (len == sizeof(uint64_t)) {
        UInt64_unpack(L, s, asLittleEndian);
    } else {
        lua_pushnil(L);
    }

    WSLUA_RETURN(1); /* The <<lua_class_UInt64,`UInt64`>> object created, or nil on failure. */
}

WSLUA_CONSTRUCTOR UInt64_new(lua_State* L) {
    /* Creates a <<lua_class_UInt64,`UInt64`>> object. */
#define WSLUA_OPTARG_UInt64_new_VALUE 1 /* A number, <<lua_class_UInt64,`UInt64`>>, <<lua_class_Int64,`Int64`>>, or string of digits
                                           to assign the value of the new <<lua_class_UInt64,`UInt64`>>. Default is 0. */
#define WSLUA_OPTARG_UInt64_new_HIGHVALUE 2 /* If this is a number and the first argument was
                                               a number, then the first will be treated as a
                                               lower 32 bits, and this is the high-order
                                               32-bit number. */
    uint64_t value = 0;

    if (lua_gettop(L) >= 1) {
        switch(lua_type(L, WSLUA_OPTARG_UInt64_new_VALUE)) {
            case LUA_TNUMBER:
                value = wslua_touint64(L, WSLUA_OPTARG_UInt64_new_VALUE);
                 if (lua_gettop(L) == 2 &&
                     lua_type(L, WSLUA_OPTARG_UInt64_new_HIGHVALUE) == LUA_TNUMBER) {
                    uint64_t h = wslua_touint64(L, WSLUA_OPTARG_UInt64_new_HIGHVALUE);
                    value &= UINT64_C(0x00000000FFFFFFFF);
                    h <<= 32; h &= UINT64_C(0xFFFFFFFF00000000);
                    value += h;
                }
               break;
            case LUA_TSTRING:
            case LUA_TUSERDATA:
                value = getUInt64(L, WSLUA_OPTARG_UInt64_new_VALUE);
                break;
            default:
                WSLUA_OPTARG_ERROR(UInt64_new,VALUE,"must be a number, UInt64, Int64, or string");
                break;
        }
    }

    pushUInt64(L,value);

    WSLUA_RETURN(1); /* The new <<lua_class_UInt64,`UInt64`>> object. */
}

WSLUA_METAMETHOD UInt64__call(lua_State* L) {
    /* Creates a <<lua_class_UInt64,`UInt64`>> object. */
    lua_remove(L,1); /* remove the table */
    WSLUA_RETURN(UInt64_new(L)); /* The new <<lua_class_UInt64,`UInt64`>> object. */
}

WSLUA_CONSTRUCTOR UInt64_max(lua_State* L) {
    /* Creates a <<lua_class_UInt64,`UInt64`>> of the maximum possible value. In other words, this should return an UInt64 object of the number 18,446,744,073,709,551,615. */
    pushUInt64(L,UINT64_MAX);
    WSLUA_RETURN(1); /* The maximum value. */
}

WSLUA_CONSTRUCTOR UInt64_min(lua_State* L) {
    /* Creates a <<lua_class_UInt64,`UInt64`>> of the minimum possible value. In other words, this should return an UInt64 object of the number 0. */
    pushUInt64(L,0);
    WSLUA_RETURN(1); /* The minimum value. */
}

WSLUA_METHOD UInt64_tonumber(lua_State* L) {
    /* Returns a Lua number of the <<lua_class_UInt64,`UInt64`>> value. This may lose precision. */
    lua_pushnumber(L,(lua_Number)(checkUInt64(L,1)));
    WSLUA_RETURN(1); /* The Lua number. */
}

WSLUA_METAMETHOD UInt64__tostring(lua_State* L) {
    /* Converts the <<lua_class_UInt64,`UInt64`>> into a string. */
    uint64_t num = getUInt64(L,1);
    char s[LUATYPE64_STRING_SIZE];
    if (snprintf(s, LUATYPE64_STRING_SIZE, "%" PRIu64,(uint64_t)num) < 0) {
        return luaL_error(L, "Error writing UInt64 to a string");
    }
    lua_pushstring(L,s);
    WSLUA_RETURN(1); /* The Lua string. */
}

WSLUA_CONSTRUCTOR UInt64_fromhex(lua_State* L) {
    /* Creates a <<lua_class_UInt64,`UInt64`>> object from the given hex string. */
#define WSLUA_ARG_UInt64_fromhex_HEX 1 /* The hex-ASCII Lua string. */
    uint64_t result = 0;
    size_t len = 0;
    const char *s = luaL_checklstring(L,WSLUA_ARG_UInt64_fromhex_HEX,&len);

    if (len > 0) {
        if (sscanf(s, "%" SCNx64, &result) != 1) {
            return luaL_error(L, "Error decoding the passed-in hex string");
        }
    }
    pushUInt64(L,result);
    WSLUA_RETURN(1); /* The new <<lua_class_UInt64,`UInt64`>> object. */
}

WSLUA_METHOD UInt64_tohex(lua_State* L) {
    /* Returns a hex string of the <<lua_class_UInt64,`UInt64`>> value. */
#define WSLUA_OPTARG_UInt64_tohex_NUMBYTES 2 /* The number of hex-chars/nibbles to generate.
                                              Negative means uppercase Default is 16. */
    uint64_t b = getUInt64(L,1);
    lua_Integer n = luaL_optinteger(L, WSLUA_OPTARG_UInt64_tohex_NUMBYTES, 16);
    const char *hexdigits = "0123456789abcdef";
    char buf[16];
    lua_Integer i;
    if (n < 0) { n = -n; hexdigits = "0123456789ABCDEF"; }
    if (n > 16) n = 16;
    for (i = n-1; i >= 0; --i) { buf[i] = hexdigits[b & 15]; b >>= 4; }
    lua_pushlstring(L, buf, (size_t)n);
    WSLUA_RETURN(1); /* The string hex. */
}

WSLUA_METHOD UInt64_higher(lua_State* L) {
    /* Returns a Lua number of the higher 32 bits of the <<lua_class_UInt64,`UInt64`>> value. */
    uint64_t num = getUInt64(L,1);
    uint64_t b = num;
    lua_Number n = 0;
    b &= UINT64_C(0xFFFFFFFF00000000);
    b >>= 32;
    n = (lua_Number)(uint32_t)(b & UINT64_C(0x00000000FFFFFFFFF));
    lua_pushnumber(L,n);
    WSLUA_RETURN(1); /* The Lua number. */
}

WSLUA_METHOD UInt64_lower(lua_State* L) {
    /* Returns a Lua number of the lower 32 bits of the <<lua_class_UInt64,`UInt64`>> value. */
    uint64_t b = getUInt64(L,1);
    lua_pushnumber(L,(uint32_t)(b & UINT64_C(0x00000000FFFFFFFFF)));
    WSLUA_RETURN(1); /* The Lua number. */
}

WSLUA_METAMETHOD UInt64__unm(lua_State* L) {
    /* Returns the <<lua_class_UInt64,`UInt64`>> in a new <<lua_class_UInt64,`UInt64`>>, since unsigned integers can't be negated. */
    pushUInt64(L,getUInt64(L,1));
    WSLUA_RETURN(1); /* The <<lua_class_UInt64,`UInt64`>> object. */
}

WSLUA_METAMETHOD UInt64__add(lua_State* L) {
    /* Adds two <<lua_class_UInt64,`UInt64`>> together and returns a new one. This may wrap the value. */
    WSLUA_MATH_OP_FUNC(UInt64,+);
}

WSLUA_METAMETHOD UInt64__sub(lua_State* L) {
    /* Subtracts two <<lua_class_UInt64,`UInt64`>> and returns a new one. This may wrap the value. */
    WSLUA_MATH_OP_FUNC(UInt64,-);
}

WSLUA_METAMETHOD UInt64__mul(lua_State* L) {
    /* Multiplies two <<lua_class_UInt64,`UInt64`>> and returns a new one. This may truncate the value. */
    WSLUA_MATH_OP_FUNC(UInt64,*);
}

WSLUA_METAMETHOD UInt64__div(lua_State* L) {
    /* Divides two <<lua_class_UInt64,`UInt64`>> and returns a new one. Integer divide, no remainder.
       Trying to divide by zero results in a Lua error.
     */
    UInt64 num1 = getUInt64(L,1);
    UInt64 num2 = getUInt64(L,2);
    if (num2 == 0) {
        return luaL_error(L, "Trying to divide UInt64 by zero");
    }
    pushUInt64(L, num1 / num2);
    WSLUA_RETURN(1); /* The <<lua_class_UInt64,`UInt64`>> result. */
}

WSLUA_METAMETHOD UInt64__mod(lua_State* L) {
    /* Divides two <<lua_class_UInt64,`UInt64`>> and returns a new one of the remainder.
       Trying to modulo by zero results in a Lua error.
     */
    UInt64 num1 = getUInt64(L,1);
    UInt64 num2 = getUInt64(L,2);
    if (num2 == 0) {
        return luaL_error(L, "Trying to modulo UInt64 by zero");
    }
    pushUInt64(L, num1 % num2);
    WSLUA_RETURN(1); /* The <<lua_class_UInt64,`UInt64`>> result. */
}

WSLUA_METAMETHOD UInt64__pow(lua_State* L) {
    /* The first <<lua_class_UInt64,`UInt64`>> is taken to the power of the second <<lua_class_UInt64,`UInt64`>>/number,
       returning a new one. This may truncate the value.
     */
    uint64_t num1 = getUInt64(L,1);
    uint64_t num2 = getUInt64(L,2);
    uint64_t result;
    if (num1 == 2) {
        result = (num2 >= 8 * (uint64_t) sizeof(uint64_t)) ? 0 : ((uint64_t)1 << num2);
    }
    else {
        for (result = 1; num2 > 0; num2 >>= 1) {
            if (num2 & 1) result *= num1;
            num1 *= num1;
        }
    }
    pushUInt64(L,result);
    WSLUA_RETURN(1); /* The <<lua_class_UInt64,`UInt64`>> object. */
}

WSLUA_METAMETHOD UInt64__eq(lua_State* L) {
    /* Returns true if both <<lua_class_UInt64,`UInt64`>> are equal. */
    WSLUA_COMP_OP_FUNC(UInt64,==);
}

WSLUA_METAMETHOD UInt64__lt(lua_State* L) {
    /* Returns true if first <<lua_class_UInt64,`UInt64`>> is less than the second. */
    WSLUA_COMP_OP_FUNC(UInt64,<);
}

WSLUA_METAMETHOD UInt64__le(lua_State* L) {
    /* Returns true if first <<lua_class_UInt64,`UInt64`>> is less than or equal to the second. */
    WSLUA_COMP_OP_FUNC(UInt64,<=);
}

WSLUA_METHOD UInt64_bnot(lua_State* L) {
    /* Returns a <<lua_class_UInt64,`UInt64`>> of the bitwise 'not' operation. */
    pushUInt64(L,~(getUInt64(L,1)));
    WSLUA_RETURN(1); /* The <<lua_class_UInt64,`UInt64`>> object. */
}

WSLUA_METHOD UInt64_band(lua_State* L) {
    /* Returns a <<lua_class_UInt64,`UInt64`>> of the bitwise 'and' operation, with the given number/`Int64`/`UInt64`.
       Note that multiple arguments are allowed.
     */
    WSLUA_BIT_OP_FUNC(UInt64,&=);
}

WSLUA_METHOD UInt64_bor(lua_State* L) {
    /* Returns a <<lua_class_UInt64,`UInt64`>> of the bitwise 'or' operation, with the given number/`Int64`/`UInt64`.
       Note that multiple arguments are allowed.
     */
    WSLUA_BIT_OP_FUNC(UInt64,|=);
}

WSLUA_METHOD UInt64_bxor(lua_State* L) {
    /* Returns a <<lua_class_UInt64,`UInt64`>> of the bitwise 'xor' operation, with the given number/`Int64`/`UInt64`.
       Note that multiple arguments are allowed.
     */
    WSLUA_BIT_OP_FUNC(UInt64,^=);
}

WSLUA_METHOD UInt64_lshift(lua_State* L) {
    /* Returns a <<lua_class_UInt64,`UInt64`>> of the bitwise logical left-shift operation, by the
       given number of bits.
     */
#define WSLUA_ARG_UInt64_lshift_NUMBITS 2 /* The number of bits to left-shift by. */
    uint64_t b = getUInt64(L,1);
    uint32_t n = wslua_checkuint32(L,WSLUA_ARG_UInt64_lshift_NUMBITS);
    pushUInt64(L,(b << n));
    WSLUA_RETURN(1); /* The <<lua_class_UInt64,`UInt64`>> object. */
}

WSLUA_METHOD UInt64_rshift(lua_State* L) {
    /* Returns a <<lua_class_UInt64,`UInt64`>> of the bitwise logical right-shift operation, by the
       given number of bits.
     */
#define WSLUA_ARG_UInt64_rshift_NUMBITS 2 /* The number of bits to right-shift by. */
    uint64_t b = getUInt64(L,1);
    uint32_t n = wslua_checkuint32(L,WSLUA_ARG_UInt64_rshift_NUMBITS);
    pushUInt64(L,(b >> n));
    WSLUA_RETURN(1); /* The <<lua_class_UInt64,`UInt64`>> object. */
}

WSLUA_METHOD UInt64_arshift(lua_State* L) {
    /* Returns a <<lua_class_UInt64,`UInt64`>> of the bitwise arithmetic right-shift operation, by the
       given number of bits.
     */
#define WSLUA_ARG_UInt64_arshift_NUMBITS 2 /* The number of bits to right-shift by. */
    uint64_t b = getUInt64(L,1);
    uint32_t n = wslua_checkuint32(L,WSLUA_ARG_UInt64_arshift_NUMBITS);
    pushUInt64(L,(b >> n));
    WSLUA_RETURN(1); /* The <<lua_class_UInt64,`UInt64`>> object. */
}

WSLUA_METHOD UInt64_rol(lua_State* L) {
    /* Returns a <<lua_class_UInt64,`UInt64`>> of the bitwise left rotation operation, by the
       given number of bits (up to 63).
     */
#define WSLUA_ARG_UInt64_rol_NUMBITS 2 /* The number of bits to roll left by. */
    uint64_t b = getUInt64(L,1);
    uint32_t n = wslua_checkuint32(L,WSLUA_ARG_UInt64_rol_NUMBITS);
    pushUInt64(L,((b << n) | (b >> (64-n))));
    WSLUA_RETURN(1); /* The <<lua_class_UInt64,`UInt64`>> object. */
}

WSLUA_METHOD UInt64_ror(lua_State* L) {
    /* Returns a <<lua_class_UInt64,`UInt64`>> of the bitwise right rotation operation, by the
       given number of bits (up to 63).
     */
#define WSLUA_ARG_UInt64_ror_NUMBITS 2 /* The number of bits to roll right by. */
    uint64_t b = getUInt64(L,1);
    uint32_t n = wslua_checkuint32(L,WSLUA_ARG_UInt64_ror_NUMBITS);
    pushUInt64(L,((b << (64-n)) | (b >> n)));
    WSLUA_RETURN(1); /* The <<lua_class_UInt64,`UInt64`>> object. */
}

WSLUA_METHOD UInt64_bswap(lua_State* L) {
    /* Returns a <<lua_class_UInt64,`UInt64`>> of the bytes swapped. This can be used to convert little-endian
       64-bit numbers to big-endian 64 bit numbers or vice versa.
     */
    uint64_t b = getUInt64(L,1);
    uint64_t result = 0;
    size_t i;
    for (i = 0; i < sizeof(uint64_t); i++) {
        result <<= 8;
        result |= (b & UINT64_C(0x00000000000000FF));
        b >>= 8;
    }
    pushUInt64(L,result);
    WSLUA_RETURN(1); /* The <<lua_class_UInt64,`UInt64`>> object. */
}

/* Gets registered as metamethod automatically by WSLUA_REGISTER_CLASS/META */
static int UInt64__gc(lua_State* L _U_) {
    return 0;
}

WSLUA_METHODS UInt64_methods[] = {
    WSLUA_CLASS_FNREG(UInt64,new),
    WSLUA_CLASS_FNREG(UInt64,max),
    WSLUA_CLASS_FNREG(UInt64,min),
    WSLUA_CLASS_FNREG(UInt64,tonumber),
    WSLUA_CLASS_FNREG(UInt64,fromhex),
    WSLUA_CLASS_FNREG(UInt64,tohex),
    WSLUA_CLASS_FNREG(UInt64,higher),
    WSLUA_CLASS_FNREG(UInt64,lower),
    WSLUA_CLASS_FNREG(UInt64,encode),
    WSLUA_CLASS_FNREG(UInt64,decode),
    WSLUA_CLASS_FNREG(UInt64,bnot),
    WSLUA_CLASS_FNREG(UInt64,band),
    WSLUA_CLASS_FNREG(UInt64,bor),
    WSLUA_CLASS_FNREG(UInt64,bxor),
    WSLUA_CLASS_FNREG(UInt64,lshift),
    WSLUA_CLASS_FNREG(UInt64,rshift),
    WSLUA_CLASS_FNREG(UInt64,arshift),
    WSLUA_CLASS_FNREG(UInt64,rol),
    WSLUA_CLASS_FNREG(UInt64,ror),
    WSLUA_CLASS_FNREG(UInt64,bswap),
    { NULL, NULL }
};

WSLUA_META UInt64_meta[] = {
    WSLUA_CLASS_MTREG(UInt64,tostring),
    WSLUA_CLASS_MTREG(UInt64,call),
    WSLUA_CLASS_MTREG(wslua,concat),
    WSLUA_CLASS_MTREG(UInt64,unm),
    WSLUA_CLASS_MTREG(UInt64,add),
    WSLUA_CLASS_MTREG(UInt64,sub),
    WSLUA_CLASS_MTREG(UInt64,mul),
    WSLUA_CLASS_MTREG(UInt64,div),
    WSLUA_CLASS_MTREG(UInt64,mod),
    WSLUA_CLASS_MTREG(UInt64,pow),
    WSLUA_CLASS_MTREG(UInt64,eq),
    WSLUA_CLASS_MTREG(UInt64,lt),
    WSLUA_CLASS_MTREG(UInt64,le),
    { NULL, NULL }
};

LUALIB_API int UInt64_register(lua_State* L) {
    WSLUA_REGISTER_CLASS(UInt64);
    return 0;
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
