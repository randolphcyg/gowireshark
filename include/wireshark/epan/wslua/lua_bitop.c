/*
** Lua BitOp -- a bit operations library for Lua 5.1/5.2.
** http://bitop.luajit.org/
**
** Copyright (C) 2008-2012 Mike Pall. All rights reserved.
**
** SPDX-License-Identifier: MIT
**
*/

#define LUA_BITOP_VERSION	"1.0.2"

#define LUA_LIB
#include <lua.h>
#include <lauxlib.h>

#include "lua_bitop.h"
#include "ws_diag_control.h"

#include <stdint.h>

typedef int32_t SBits;
typedef uint32_t UBits;

typedef union {
  lua_Number n;
#if defined(LUA_NUMBER_DOUBLE) || defined(LUA_FLOAT_DOUBLE)
  uint64_t b;
#else
  UBits b;
#endif
} BitNum;

/* Convert argument to bit type. */
static UBits barg(lua_State *L, int idx)
{
  BitNum bn;
  UBits b;
  bn.n = luaL_checknumber(L, idx);
#if defined(LUA_NUMBER_DOUBLE) || defined(LUA_FLOAT_DOUBLE)
  bn.n += 6755399441055744.0;  /* 2^52+2^51 */
#ifdef SWAPPED_DOUBLE
  b = (UBits)(bn.b >> 32);
#else
  b = (UBits)bn.b;
#endif
#elif defined(LUA_NUMBER_INT)       || defined(LUA_INT_INT) || \
      defined(LUA_NUMBER_LONG)      || defined(LUA_INT_LONG) || \
      defined(LUA_NUMBER_LONGLONG)  || defined(LUA_INT_LONGLONG) || \
      defined(LUA_NUMBER_LONG_LONG) || defined(LUA_NUMBER_LLONG)
  if (sizeof(UBits) == sizeof(lua_Number))
    b = bn.b;
  else
    b = (UBits)(SBits)bn.n;
#elif defined(LUA_NUMBER_FLOAT) || defined(LUA_FLOAT_FLOAT)
#error "A 'float' lua_Number type is incompatible with this library"
#else
#error "Unknown number type, check LUA_NUMBER_*, LUA_FLOAT_*, LUA_INT_* in luaconf.h"
#endif
  return b;
}

/* Return bit type. */
#if LUA_VERSION_NUM < 503
#define BRET(b)  lua_pushnumber(L, (lua_Number)(SBits)(b)); return 1;
#else
#define BRET(b)  lua_pushinteger(L, (lua_Integer)(SBits)(b)); return 1;
#endif

static int bit_tobit(lua_State *L) { BRET(barg(L, 1)) }
static int bit_bnot(lua_State *L) { BRET(~barg(L, 1)) }

#define BIT_OP(func, opr) \
  static int func(lua_State *L) { int i; UBits b = barg(L, 1); \
    for (i = lua_gettop(L); i > 1; i--) { b opr barg(L, i); } BRET(b) }
BIT_OP(bit_band, &=)
BIT_OP(bit_bor, |=)
BIT_OP(bit_bxor, ^=)

#define bshl(b, n)  (b << n)
#define bshr(b, n)  (b >> n)
#define bsar(b, n)  ((SBits)b >> n)
#define brol(b, n)  ((b << n) | (b >> (32-n)))
#define bror(b, n)  ((b << (32-n)) | (b >> n))
#define BIT_SH(func, fn) \
  static int func(lua_State *L) { \
    UBits b = barg(L, 1); UBits n = barg(L, 2) & 31; BRET(fn(b, n)) }
BIT_SH(bit_lshift, bshl)
BIT_SH(bit_rshift, bshr)
BIT_SH(bit_arshift, bsar)
BIT_SH(bit_rol, brol)
BIT_SH(bit_ror, bror)

static int bit_bswap(lua_State *L)
{
  UBits b = barg(L, 1);
  b = (b >> 24) | ((b >> 8) & 0xff00) | ((b & 0xff00) << 8) | (b << 24);
  BRET(b)
}

static int bit_tohex(lua_State *L)
{
  UBits b = barg(L, 1);
  SBits n = lua_isnone(L, 2) ? 8 : (SBits)barg(L, 2);
  const char *hexdigits = "0123456789abcdef";
  char buf[8];
  int i;
  if (n < 0) { n = -n; hexdigits = "0123456789ABCDEF"; }
  if (n > 8) n = 8;
  for (i = (int)n; --i >= 0; ) { buf[i] = hexdigits[b & 15]; b >>= 4; }
  lua_pushlstring(L, buf, (size_t)n);
  return 1;
}

static const struct luaL_Reg bit_funcs[] = {
  { "tobit",	bit_tobit },
  { "bnot",	bit_bnot },
  { "band",	bit_band },
  { "bor",	bit_bor },
  { "bxor",	bit_bxor },
  { "lshift",	bit_lshift },
  { "rshift",	bit_rshift },
  { "arshift",	bit_arshift },
  { "rol",	bit_rol },
  { "ror",	bit_ror },
  { "bswap",	bit_bswap },
  { "tohex",	bit_tohex },
  { NULL, NULL }
};

/* Signed right-shifts are implementation-defined per C89/C99.
** But the de facto standard are arithmetic right-shifts on two's
** complement CPUs. This behaviour is required here, so test for it.
*/
#define BAD_SAR		(bsar(-8, 2) != (SBits)-2)

LUALIB_API int luaopen_bit(lua_State *L)
{
  UBits b;
#if LUA_VERSION_NUM < 503
  lua_pushnumber(L, (lua_Number)1437217655L);
#else
  lua_pushinteger(L, (lua_Integer)1437217655L);
#endif
  b = barg(L, -1);
  if (b != (UBits)1437217655L || BAD_SAR) {  /* Perform a simple self-test. */
    const char *msg = "compiled with incompatible luaconf.h";
#if defined(LUA_NUMBER_DOUBLE) || defined(LUA_FLOAT_DOUBLE)
#ifdef _WIN32
    if (b == (UBits)1610612736L)
      msg = "use D3DCREATE_FPU_PRESERVE with DirectX";
#endif
    if (b == (UBits)1127743488L)
      msg = "not compiled with SWAPPED_DOUBLE";
#endif
DIAG_OFF(unreachable-code)
    if (BAD_SAR)
      msg = "arithmetic right-shift broken";
DIAG_ON(unreachable-code)
    luaL_error(L, "bit library self-test failed (%s)", msg);
  }

  luaL_newlib(L, bit_funcs);
  lua_setglobal(L, "bit"); /* added for wireshark */
  return 0; /* changed from 1 to 0 for wireshark, since lua_setglobal now pops the table */
}

