/* packet-knxip_decrypt.c
 * Decryption keys and decryption functions for KNX/IP Dissector
 * Copyright 2018, ise GmbH <Ralf.Nasilowski@ise.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#define WS_LOG_DOMAIN "packet-knxip"

#include <wsutil/file_util.h>
#include <epan/proto.h>
#include "packet-knxip_decrypt.h"
#include <epan/wmem_scopes.h>
#include <wsutil/wsgcrypt.h>
#include <wsutil/strtoi.h>
#include <wsutil/wslog.h>
#include <wsutil/inet_addr.h>

#define TEXT_BUFFER_SIZE  128

#define IPA_SIZE  4  // = size of IPv4 address

#define BASE64_KNX_KEY_LENGTH  24  // = length of base64 encoded KNX key

struct knx_keyring_mca_keys* knx_keyring_mca_keys;
struct knx_keyring_ga_keys* knx_keyring_ga_keys;
struct knx_keyring_ga_senders* knx_keyring_ga_senders;
struct knx_keyring_ia_keys* knx_keyring_ia_keys;
struct knx_keyring_ia_seqs* knx_keyring_ia_seqs;

// Encrypt 16-byte block via AES
static void encrypt_block( const uint8_t key[ KNX_KEY_LENGTH ], const uint8_t plain[ KNX_KEY_LENGTH ], uint8_t p_crypt[ KNX_KEY_LENGTH ] )
{
  gcry_cipher_hd_t cryptor = NULL;
  gcry_cipher_open( &cryptor, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC, 0 );
  gcry_cipher_setkey( cryptor, key, KNX_KEY_LENGTH );
  gcry_cipher_encrypt( cryptor, p_crypt, KNX_KEY_LENGTH, plain, KNX_KEY_LENGTH );
  gcry_cipher_close( cryptor );
}

// Create B_0 for CBC-MAC
static void build_b0( uint8_t p_result[ KNX_KEY_LENGTH ], const uint8_t* nonce, uint8_t nonce_length )
{
  DISSECTOR_ASSERT( nonce_length <= KNX_KEY_LENGTH );
  if( nonce_length ) memcpy( p_result, nonce, nonce_length );
  memset( p_result + nonce_length, 0, KNX_KEY_LENGTH - nonce_length );
}

// Create Ctr_0 for CCM encryption/decryption
static void build_ctr0( uint8_t p_result[ KNX_KEY_LENGTH ], const uint8_t* nonce, uint8_t nonce_length )
{
  build_b0( p_result, nonce, nonce_length );
  p_result[ KNX_KEY_LENGTH - 2 ] = 0xFF;
}

// Calculate MAC for KNX IP Security or KNX Data Security
void knx_ccm_calc_cbc_mac(uint8_t p_mac[ KNX_KEY_LENGTH ], const uint8_t key[ KNX_KEY_LENGTH ],
  const uint8_t* a_bytes, int a_length, const uint8_t* p_bytes, int p_length,
  const uint8_t b_0[ KNX_KEY_LENGTH ] )
{
  uint8_t plain[ KNX_KEY_LENGTH ];
  uint8_t b_pos;

  // Add B_0
  memcpy( plain, b_0, KNX_KEY_LENGTH );
  encrypt_block( key, plain, p_mac );

  // Add a_length
  plain[ 0 ] = (uint8_t) ((a_length >> 8) ^ p_mac[ 0 ]);
  plain[ 1 ] = (uint8_t) ((a_length & 0xFF) ^ p_mac[ 1 ]);
  b_pos = 2;

  // Add a_bytes directly followed by p_bytes
  while( a_length || p_length )
  {
    while( a_length && b_pos < KNX_KEY_LENGTH )
    {
      plain[ b_pos ] = *a_bytes++ ^ p_mac[ b_pos ];
      --a_length;
      ++b_pos;
    }

    while( p_length && b_pos < KNX_KEY_LENGTH )
    {
      plain[ b_pos ] = *p_bytes++ ^ p_mac[ b_pos ];
      --p_length;
      ++b_pos;
    }

    while( b_pos < KNX_KEY_LENGTH )
    {
      plain[ b_pos ] = p_mac[ b_pos ];
      ++b_pos;
    }

    encrypt_block( key, plain, p_mac );

    b_pos = 0;
  }
}

// Calculate MAC for KNX IP Security, using 6-byte Sequence ID
void knxip_ccm_calc_cbc_mac( uint8_t p_mac[ KNX_KEY_LENGTH ], const uint8_t key[ KNX_KEY_LENGTH ],
  const uint8_t* a_bytes, int a_length, const uint8_t* p_bytes, int p_length,
  const uint8_t* nonce, uint8_t nonce_length )
{
  uint8_t b_0[ KNX_KEY_LENGTH ];
  build_b0( b_0, nonce, nonce_length );
  b_0[ KNX_KEY_LENGTH - 2 ] = (uint8_t) (p_length >> 8);
  b_0[ KNX_KEY_LENGTH - 1 ] = (uint8_t) (p_length & 0xFF);
  knx_ccm_calc_cbc_mac( p_mac, key, a_bytes, a_length, p_bytes, p_length, b_0 );
}

// Encrypt for KNX IP Security or KNX Data Security
uint8_t* knx_ccm_encrypt( uint8_t* p_result, const uint8_t key[ KNX_KEY_LENGTH ], const uint8_t* p_bytes, int p_length,
  const uint8_t* mac, uint8_t mac_length, const uint8_t ctr_0[ KNX_KEY_LENGTH ], uint8_t s0_bytes_used_for_mac )
{
  if( p_length >= 0 && !(p_length && !p_bytes) )
  {
    // NB: mac_length = 16 (for IP Security), or 4 (for Data Security)

    uint8_t* result = p_result ? p_result : (uint8_t*) wmem_alloc( wmem_packet_scope(), p_length + mac_length );

    uint8_t* dest = result;

    uint8_t ctr[ KNX_KEY_LENGTH ];
    uint8_t mask[ KNX_KEY_LENGTH ];
    uint8_t mask_0[ KNX_KEY_LENGTH ];
    uint8_t b_pos;

    // Encrypt ctr_0 for mac
    memcpy( ctr, ctr_0, KNX_KEY_LENGTH );
    encrypt_block( key, ctr, mask_0 );

    // Encrypt p_bytes with rest of S_0, only if mac_length < 16.
    b_pos = s0_bytes_used_for_mac;
    while (p_length && b_pos < KNX_KEY_LENGTH )
    {
      *dest++ = mask_0[b_pos++] ^ *p_bytes++;
      --p_length;
    }

    // Encrypt p_bytes
    while( p_length )
    {
      // Increment and encrypt ctr
      ++ctr[ KNX_KEY_LENGTH - 1 ];
      encrypt_block( key, ctr, mask );

      // Encrypt input block via encrypted ctr
      b_pos = 0;
      while( p_length && b_pos < KNX_KEY_LENGTH )
      {
        *dest++ = mask[ b_pos++] ^ *p_bytes++;
        --p_length;
      }
    }

    if( mac )
    {
      if( mac_length > KNX_KEY_LENGTH )
      {
        mac_length = KNX_KEY_LENGTH;
      }

      // Encrypt and append mac
      b_pos = 0;
      while( mac_length )
      {
        *dest++ = mask_0[ b_pos++] ^ *mac++;
        --mac_length;
      }
    }

    return result;
  }

  return NULL;
}

// Encrypt for KNX IP Security (with 16-byte MAC and Nonce based on 6-byte Sequence ID)
uint8_t* knxip_ccm_encrypt( uint8_t* p_result, const uint8_t key[ KNX_KEY_LENGTH ], const uint8_t* p_bytes, int p_length,
  const uint8_t mac[KNX_KEY_LENGTH], const uint8_t* nonce, uint8_t nonce_length )
{
  uint8_t ctr_0[ KNX_KEY_LENGTH ];
  build_ctr0( ctr_0, nonce, nonce_length );
  return knx_ccm_encrypt( p_result, key, p_bytes, p_length, mac, KNX_KEY_LENGTH, ctr_0, KNX_KEY_LENGTH );
}

// Decrypt for KNX-IP Security (with 16-byte MAC and Nonce based on 6-byte Sequence ID)
uint8_t* knxip_ccm_decrypt( uint8_t* p_result, const uint8_t key[ KNX_KEY_LENGTH ], const uint8_t* crypt, int crypt_length,
  const uint8_t* nonce, uint8_t nonce_length )
{
  int p_length = crypt_length - KNX_KEY_LENGTH;
  uint8_t ctr_0[ KNX_KEY_LENGTH ];
  build_ctr0( ctr_0, nonce, nonce_length );
  return knx_ccm_encrypt( p_result, key, crypt, p_length, crypt + p_length, KNX_KEY_LENGTH, ctr_0, KNX_KEY_LENGTH );
}

static void fprintf_hex( FILE* f, const uint8_t* data, uint8_t length )
{
  for( ; length; --length ) fprintf( f, " %02X", *data++ );
  fputc( '\n', f );
}

static void clear_keyring_data( void )
{
  while( knx_keyring_mca_keys )
  {
    struct knx_keyring_mca_keys* mca_key = knx_keyring_mca_keys;
    knx_keyring_mca_keys = mca_key->next;
    wmem_free( wmem_epan_scope(), mca_key );
  }

  while( knx_keyring_ga_keys )
  {
    struct knx_keyring_ga_keys* ga_key = knx_keyring_ga_keys;
    knx_keyring_ga_keys = ga_key->next;
    wmem_free( wmem_epan_scope(), ga_key );
  }

  while( knx_keyring_ga_senders )
  {
    struct knx_keyring_ga_senders* ga_sender = knx_keyring_ga_senders;
    knx_keyring_ga_senders = ga_sender->next;
    wmem_free( wmem_epan_scope(), ga_sender );
  }

  while( knx_keyring_ia_keys )
  {
    struct knx_keyring_ia_keys* ia_key = knx_keyring_ia_keys;
    knx_keyring_ia_keys = ia_key->next;
    wmem_free( wmem_epan_scope(), ia_key );
  }

  while( knx_keyring_ia_seqs )
  {
    struct knx_keyring_ia_seqs* ia_seq = knx_keyring_ia_seqs;
    knx_keyring_ia_seqs = ia_seq->next;
    wmem_free( wmem_epan_scope(), ia_seq );
  }
}

// Read IP address
static void read_ip_addr( uint8_t result[ 4 ], const char* text )
{
  ws_in4_addr value = 0;
  if( ws_inet_pton4( text, &value ) )
    memcpy( result, &value, 4 );
  else
    memset( result, 0, 4 );
}

// Read KNX group address
static uint16_t read_ga( const char* text )
{
  unsigned a[ 3 ];
  int n = sscanf( text, "%u/%u/%u", a, a + 1, a + 2 );
  return
    (n == 1) ? (uint16_t) a[ 0 ] :
    (n == 2) ? (uint16_t) ((a[ 0 ] << 11) | a[ 1 ]) :
    (n == 3) ? (uint16_t) ((a[ 0 ] << 11) | (a[ 1 ] << 8) | a[ 2 ]) :
    0;
}

// Read KNX individual address
static uint16_t read_ia( const char* text )
{
  unsigned a[ 3 ];
  int n = sscanf( text, "%u.%u.%u", a, a + 1, a + 2 );
  return
    (n == 1) ? (uint16_t) a[ 0 ] :
    (n == 2) ? (uint16_t) ((a[ 0 ] << 8) | a[ 1 ]) :
    (n == 3) ? (uint16_t) ((a[ 0 ] << 12) | (a[ 1 ] << 8) | a[ 2 ]) :
    0;
}

// Read 6-byte sequence number from decimal representation
static uint64_t read_seq( const char* text )
{
  uint64_t result;
  return ws_strtou64( text, NULL, &result ) ? result : 0;
}

// Decrypt key
static void decrypt_key( uint8_t key[] _U_, uint8_t password_hash[] _U_, uint8_t created_hash[] _U_ )
{
  // TODO: decrypt as AES128-CBC(key, password_hash, created_hash)
}

// Decode and decrypt key
static void decode_and_decrypt_key( uint8_t key[ BASE64_KNX_KEY_LENGTH + 1 ], const char* text, uint8_t password_hash[], uint8_t created_hash[] )
{
  size_t out_len;
  snprintf( (char*) key, BASE64_KNX_KEY_LENGTH + 1, "%s", text );
  g_base64_decode_inplace( (char*) key, &out_len );
  decrypt_key( key, password_hash, created_hash );
}

// Add MCA <-> key association
static void add_mca_key( const uint8_t mca[ IPA_SIZE ], const char* text, uint8_t password_hash[], uint8_t created_hash[], FILE* f2 )
{
  int text_length = (int) strlen( text );

  if( text_length == BASE64_KNX_KEY_LENGTH )
  {
    uint8_t key[ BASE64_KNX_KEY_LENGTH + 1 ];
    struct knx_keyring_mca_keys** mca_keys_next;
    struct knx_keyring_mca_keys* mca_key;

    decode_and_decrypt_key( key, text, password_hash, created_hash );

    mca_keys_next = &knx_keyring_mca_keys;

    while( (mca_key = *mca_keys_next) != NULL )
    {
      if( memcmp( mca_key->mca, mca, IPA_SIZE ) == 0 )
      {
        if( memcmp( mca_key->key, key, KNX_KEY_LENGTH ) == 0 )
        {
          return;
        }
      }

      mca_keys_next = &mca_key->next;
    }

    if( f2 )
    {
      fprintf( f2, "MCA %u.%u.%u.%u key", mca[ 0 ], mca[ 1 ], mca[ 2 ], mca[ 3 ] );
      fprintf_hex( f2, key, KNX_KEY_LENGTH );
    }

    mca_key = wmem_new(wmem_epan_scope(), struct knx_keyring_mca_keys);

    if( mca_key )
    {
      mca_key->next = NULL;
      memcpy( mca_key->mca, mca, IPA_SIZE );
      memcpy( mca_key->key, key, KNX_KEY_LENGTH );

      *mca_keys_next = mca_key;
    }
  }
}

// Add GA <-> key association
static void add_ga_key( uint16_t ga, const char* text, uint8_t password_hash[], uint8_t created_hash[], FILE* f2 )
{
  int text_length = (int) strlen( text );

  if( text_length == BASE64_KNX_KEY_LENGTH )
  {
    uint8_t key[ BASE64_KNX_KEY_LENGTH + 1 ];
    struct knx_keyring_ga_keys** ga_keys_next;
    struct knx_keyring_ga_keys* ga_key;

    decode_and_decrypt_key( key, text, password_hash, created_hash );

    ga_keys_next = &knx_keyring_ga_keys;

    while( (ga_key = *ga_keys_next) != NULL )
    {
      if( ga_key->ga == ga )
      {
        if( memcmp( ga_key->key, key, KNX_KEY_LENGTH ) == 0 )
        {
          return;
        }
      }

      ga_keys_next = &ga_key->next;
    }

    if( f2 )
    {
      fprintf( f2, "GA %u/%u/%u key", (ga >> 11) & 0x1F, (ga >> 8) & 0x7, ga & 0xFF );
      fprintf_hex( f2, key, KNX_KEY_LENGTH );
    }

    ga_key = wmem_new(wmem_epan_scope(), struct knx_keyring_ga_keys);

    if( ga_key )
    {
      ga_key->next = NULL;
      ga_key->ga = ga;
      memcpy( ga_key->key, key, KNX_KEY_LENGTH );

      *ga_keys_next = ga_key;
    }
  }
}

// Add GA <-> sender association
static void add_ga_sender( uint16_t ga, const char* text, FILE* f2 )
{
  uint16_t ia = read_ia( text );
  struct knx_keyring_ga_senders** ga_senders_next = &knx_keyring_ga_senders;
  struct knx_keyring_ga_senders* ga_sender;

  while( (ga_sender = *ga_senders_next) != NULL )
  {
    if( ga_sender->ga == ga )
    {
      if( ga_sender->ia == ia )
      {
        return;
      }
    }

    ga_senders_next = &ga_sender->next;
  }

  if( f2 )
  {
    fprintf( f2, "GA %u/%u/%u sender %u.%u.%u\n", (ga >> 11) & 0x1F, (ga >> 8) & 0x7, ga & 0xFF, (ia >> 12) & 0xF, (ia >> 8) & 0xF, ia & 0xFF );
  }

  ga_sender = wmem_new(wmem_epan_scope(), struct knx_keyring_ga_senders);

  if( ga_sender )
  {
    ga_sender->next = NULL;
    ga_sender->ga = ga;
    ga_sender->ia = ia;

    *ga_senders_next = ga_sender;
  }
}

// Add IA <-> key association
static void add_ia_key( uint16_t ia, const char* text, uint8_t password_hash[], uint8_t created_hash[], FILE* f2 )
{
  int text_length = (int) strlen( text );

  if( text_length == BASE64_KNX_KEY_LENGTH )
  {
    uint8_t key[ BASE64_KNX_KEY_LENGTH + 1 ];
    struct knx_keyring_ia_keys** ia_keys_next;
    struct knx_keyring_ia_keys* ia_key;

    decode_and_decrypt_key( key, text, password_hash, created_hash );

    ia_keys_next = &knx_keyring_ia_keys;

    while( (ia_key = *ia_keys_next) != NULL )
    {
      if( ia_key->ia == ia )
      {
        if( memcmp( ia_key->key, key, KNX_KEY_LENGTH ) == 0 )
        {
          return;
        }
      }

      ia_keys_next = &ia_key->next;
    }

    if( f2 )
    {
      fprintf( f2, "IA %u.%u.%u key", (ia >> 12) & 0xF, (ia >> 8) & 0xF, ia & 0xFF );
      fprintf_hex( f2, key, KNX_KEY_LENGTH );
    }

    ia_key = wmem_new(wmem_epan_scope(), struct knx_keyring_ia_keys);

    if( ia_key )
    {
      ia_key->next = NULL;
      ia_key->ia = ia;
      memcpy( ia_key->key, key, KNX_KEY_LENGTH );

      *ia_keys_next = ia_key;
    }
  }
}

// Add IA <-> sequence number association
static void add_ia_seq( uint16_t ia, const char* text, FILE* f2 )
{
  uint64_t seq = read_seq( text );

  struct knx_keyring_ia_seqs** ia_seqs_next = &knx_keyring_ia_seqs;
  struct knx_keyring_ia_seqs* ia_seq;

  while( (ia_seq = *ia_seqs_next) != NULL )
  {
    if( ia_seq->ia == ia )
    {
      if( ia_seq->seq == seq )
      {
        return;
      }
    }

    ia_seqs_next = &ia_seq->next;
  }

  if( f2 )
  {
    fprintf( f2, "IA %u.%u.%u SeqNr %" PRIu64 "\n", (ia >> 12) & 0xF, (ia >> 8) & 0xF, ia & 0xFF, seq );
  }

  ia_seq = wmem_new(wmem_epan_scope(), struct knx_keyring_ia_seqs);

  if( ia_seq )
  {
    ia_seq->next = NULL;
    ia_seq->ia = ia;
    ia_seq->seq = seq;

    *ia_seqs_next = ia_seq;
  }
}

// Calculate PBKDF2(HMAC-SHA256, password, "1.keyring.ets.knx.org", 65536, 128)
static void make_password_hash( uint8_t password_hash[] _U_, const char* password _U_ )
{
  // TODO: password_hash = PBKDF2(HMAC-SHA256, password, "1.keyring.ets.knx.org", 65536, 128)
}

// Calculate MSB128(SHA256(created))
static void make_created_hash( uint8_t created_hash[] _U_, const char* created _U_ )
{
  // TODO: created_hash = MSB128(SHA256(created))
}

// Read KNX security key info from keyring XML file.
//
// An example keyring XML file is
//   "test/keys/knx_keyring.xml".
//
// Corresponding test is
//   suite_decryption.case_decrypt_knxip.test_knxip_keyring_xml_import
//
// We do not use LibXml2 here, because
// (1) we want to be platform independent,
// (2) we just want to extract some data from the keyring XML file,
// (3) we want to avoid the complicated recursive DOM processing implied by LibXml2.
//
// Resulting decoded and decrypted 16-byte keys with context info are optionally written to a "key info" text file.
// This may be useful, as these keys are not directly available from the keyring XML file .
void read_knx_keyring_xml_file( const char* key_file, const char* password, const char* key_info_file )
{
  // Clear old keyring data
  clear_keyring_data();

  // Read new data from keyring XML file
  FILE* f = ws_fopen( key_file, "r" );

  // Optionally write extracted data to key info file
  FILE* f2 = (!key_info_file || !*key_info_file) ? NULL :
    (strcmp( key_info_file, "-" ) == 0) ? stdout :
    ws_fopen( key_info_file, "w" );

  if( f )
  {
    uint8_t backbone_mca[ IPA_SIZE ];
    uint8_t backbone_mca_valid = 0;
    uint16_t group_ga = 0;
    uint8_t group_ga_valid = 0;
    uint16_t device_ia = 0;
    uint8_t device_ia_valid = 0;
    char name[ TEXT_BUFFER_SIZE ];
    char value[ TEXT_BUFFER_SIZE ];
    uint8_t password_hash[ KNX_KEY_LENGTH ];
    uint8_t created_hash[ KNX_KEY_LENGTH ];
    char tag_name[ TEXT_BUFFER_SIZE ];
    uint8_t tag_name_done = 0;
    uint8_t tag_end = 0;
    uint8_t in_tag = 0;

    memset( backbone_mca, 0, IPA_SIZE );
    *name = '\0';
    *value = '\0';
    memset( password_hash, 0, KNX_KEY_LENGTH );
    memset( created_hash, 0, KNX_KEY_LENGTH );
    *tag_name = '\0';

    make_password_hash( password_hash, password );

    ws_debug( "%s:", key_file );

    int c = fgetc( f );

    while( c >= 0 )
    {
      if( c == '<' )  // tag start
      {
        in_tag = 1;
        tag_end = 0;
        *tag_name = 0;
        tag_name_done = 0;
        *name = '\0';
        *value = '\0';
      }
      else if( c == '>' )  // tag end
      {
        in_tag = 0;
      }
      else if( c == '/' )
      {
        if( in_tag )  // "</" or "/>"
        {
          tag_end = 1;
          *tag_name = 0;
          tag_name_done = 0;
          *name = '\0';
          *value = '\0';
        }
      }
      else if( g_ascii_isalpha( c ) || c == '_' )  // possibly tag name, or attribute name
      {
        size_t length = 0;
        name[ length++ ] = (char) c;
        while( (c = fgetc( f )) >= 0 )
        {
          if( g_ascii_isalnum( c ) || c == '_' )
          {
            if( length < sizeof name - 1 )
            {
              name[ length++ ] = (char) c;
            }
          }
          else
          {
            break;
          }
        }
        name[ length ] = '\0';
        *value = '\0';

        if( !tag_name_done )  // tag name
        {
          snprintf( tag_name, sizeof tag_name, "%s", name );
          *name = '\0';
          tag_name_done = 1;
        }
        else  // Check for name="value" construct
        {
          while( c >= 0 && g_ascii_isspace( c ) ) c = fgetc( f );

          if( c == '=' )
          {
            while( (c = fgetc( f )) >= 0 && g_ascii_isspace( c ) );

            if( c == '"' )
            {
              length = 0;

              while( (c = fgetc( f )) >= 0 )
              {
                if( c == '"' )
                {
                  c = fgetc( f );
                  if( c != '"' )
                  {
                    break;
                  }
                }
                if( length < sizeof value - 1 )
                {
                  value[ length++ ] = (char) c;
                }
              }

              value[ length ] = 0;

              if( !tag_end )
              {
                // Found name="value" construct between < and >
                ws_debug( "%s %s=%s", tag_name, name, value );

                // Process name/value pair
                if( strcmp( tag_name, "Keyring" ) == 0 )
                {
                  if( strcmp( name, "Created" ) == 0 )
                  {
                    make_created_hash( created_hash, value );
                  }
                }
                else if( strcmp( tag_name, "Backbone" ) == 0 )
                {
                  group_ga_valid = 0;
                  device_ia_valid = 0;

                  if( strcmp( name, "MulticastAddress" ) == 0 )
                  {
                    read_ip_addr( backbone_mca, value );
                    backbone_mca_valid = 1;
                  }
                  else if( strcmp( name, "Key" ) == 0 )
                  {
                    if( backbone_mca_valid )
                    {
                      add_mca_key( backbone_mca, value, password_hash, created_hash, f2 );
                    }
                  }
                }
                else if( strcmp( tag_name, "Group" ) == 0 )
                {
                  backbone_mca_valid = 0;
                  device_ia_valid = 0;

                  if( strcmp( name, "Address" ) == 0 )
                  {
                    group_ga = read_ga( value );
                    group_ga_valid = 1;
                  }
                  else if( strcmp( name, "Key" ) == 0 )
                  {
                    if( group_ga_valid )
                    {
                      add_ga_key( group_ga, value, password_hash, created_hash, f2 );
                    }
                  }
                  else if( strcmp( name, "Senders" ) == 0 )
                  {
                    if( group_ga_valid )
                    {
                      // Add senders given by space separated list of KNX IAs
                      static const char delim[] = " ,";
                      const char* token = strtok( value, delim );
                      while( token )
                      {
                        add_ga_sender( group_ga, token, f2 );
                        token = strtok( NULL, delim );
                      }
                    }
                  }
                }
                else if( strcmp( tag_name, "Device" ) == 0 )
                {
                  backbone_mca_valid = 0;
                  group_ga_valid = 0;

                  if( strcmp( name, "IndividualAddress" ) == 0 )
                  {
                    device_ia = read_ia( value );
                    device_ia_valid = 1;
                  }
                  else if( strcmp( name, "ToolKey" ) == 0 )
                  {
                    if( device_ia_valid )
                    {
                      add_ia_key( device_ia, value, password_hash, created_hash, f2 );
                    }
                  }
                  else if( strcmp( name, "SequenceNumber" ) == 0 )
                  {
                    if( device_ia_valid )
                    {
                      add_ia_seq( device_ia, value, f2 );
                    }
                  }
                }
                else
                {
                  backbone_mca_valid = 0;
                  group_ga_valid = 0;
                  device_ia_valid = 0;
                }
              }
            }
          }
        }

        if( c < 0 )  // EOF
        {
          break;
        }

        continue;
      }
      else
      {
        if( !g_ascii_isspace( c ) )
        {
          tag_name_done = 1;
          *name = '\0';
          *value = '\0';
        }
      }

      c = fgetc( f );
    }

    fclose( f );
  }

  if( f2 && f2 != stdout )
  {
    fclose( f2 );
  }
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
