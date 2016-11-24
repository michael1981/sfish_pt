#TRUSTED 53368b457aef99ebf74687ccaac61b0a156cd21ee42927a926fb10ea1987f8d9644ac94c05ad75e3375d92c007581354f50a6c09338280853dfbaee957ebc5f7bfbd1dfe95da3e7895eaae66c6889774d87985116ee1ad388a20889c896067a19a4fca7c51cbd1534fefb4ceb6f5edb156cdec330790c9fe54238d2133ba9046cb321098ff2e3bda6542416be6173d6982522dc8dacb9e82f895c603f917a1e73290cfb574feff1cdd35936ddb9abb5aa59dd93093ceb13a90ca800096690570c91a5402fe504d948b0019ed54660cb08e47990adeb80251cf6713a4dbbaf577bd2f0440349d3bcb32d606735f3eb2f2ffbfaaf1adbc46c6dd4d5be92f859a7dc89b56b150b1995a6c7a126ba002fc77583ab141cb215c928d56e5515c42b2a8614c91c3b282b269b2f8160d36bb0b73a62b08cfe55ac9cc5576fbc0435065f8ca2a4f39a2f43199954b7cb26fea645da3b7ff336333096adec4100d6c4049c27c83a54858b5a33aabe4496abc99f8f6bac12fe136565183da9aceef89ebbc4def79860af5740eec0cd55deb5f167809db99aef0c91404adfdf32b85026d15787500b93f72950373d0c7637e63b19523a5634f5718bc068dfd4bf7867afc57c0d4576f49459f2466d6cb6c618f1ce7f9fabfe4f4c152bd12c55d04b32fa2204367bcf04a0caf2bbf4e3ef3f27dfcfe4e40089010f65eec71f5c0730113d02e50
# -*- Fundamental -*-
#
# 
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# @NOGPL@
#
# byte_func.inc
# Revision: 1.7
#


BYTE_ORDER_BIG_ENDIAN  		= 1;
BYTE_ORDER_LITTLE_ENDIAN 	= 2;

ByteOrder = BYTE_ORDER_BIG_ENDIAN;

function set_byte_order()
{
 ByteOrder = _FCT_ANON_ARGS[0];
}

function mkbyte()
{
 local_var l;
 l = _FCT_ANON_ARGS[0];
 return raw_string(l & 0xff);
}

function mkword()
{
 local_var l;
 l = _FCT_ANON_ARGS[0];

 if ( ByteOrder == BYTE_ORDER_BIG_ENDIAN )
 	return  raw_string((l >> 8) & 0xFF, l & 0xFF);
 else
 	return  raw_string(l & 0xff, (l >> 8) & 0xff);
}


function mkdword()
{
 local_var l;
 l = _FCT_ANON_ARGS[0];

 if ( ByteOrder == BYTE_ORDER_BIG_ENDIAN )
	 return  raw_string( (l >> 24 ) & 0xff,
		     	     (l >> 16 ) & 0xff,
		     	     (l >>  8 ) & 0xff,
		     	     (l)   & 0xff);
 else
	 return  raw_string( l & 0xff,
		     	    (l >> 8) & 0xff,
		            (l >> 16) & 0xff,
		            (l >> 24)   & 0xff);
}

# NASL3 uses 32 bits integers
function getqword_shift(blob, pos, shift)
{
 local_var shift8, shift1, xx, yy, i, start, end;

 if ( strlen(blob) < pos + 8 || shift < 0 )
	return NULL;
 if (shift >= 64) return 0;
 shift8 = shift / 8;
 shift1 = shift - 8 * shift8;

 yy = 0; xx = 0;
 if ( ByteOrder == BYTE_ORDER_BIG_ENDIAN )
 {
  start = 4 - shift8; if (start < 0) start = 0;
  for (i = start; i <= 7 - shift8; i ++)
     xx = (xx << 8) | ord(blob[pos+i]);
   xx >>>= shift1;
   if (shift < 32) yy = ord(blob[pos + 3 - shift8]);
   if (shift1 > 0) yy <<= (8 - shift1) + 24; else yy = 0;
 }
 else
 {
   end = shift8 + 3; if (end > 7) end = 7;
   for (i = end; i >= shift8; i --)
     xx = (xx << 8) | ord(blob[pos+i]);
   xx >>>= shift1;
   if (shift < 32) yy = ord(blob[pos + shift8 + 4]);
   if (shift1 > 0) yy <<= (8 - shift1) + 24; else yy = 0;
 }
 xx = xx | yy;
 return xx;
}

function getdword(blob, pos)
{
 local_var l, s;
 if ( strlen(blob) < pos + 4 )
	return NULL;

 s = substr(blob, pos, pos + 3);
 if ( ByteOrder == BYTE_ORDER_BIG_ENDIAN )
  return ord(s[0]) << 24 | ord(s[1]) << 16 | ord(s[2]) << 8 | ord(s[3]);
 else
  return ord(s[0]) | ord(s[1]) << 8 | ord(s[2]) << 16 | ord(s[3]) << 24;
}

function getword(blob, pos)
{
 local_var l, s;
 if ( strlen(blob) < pos + 2 )
	return NULL;
 s = substr(blob, pos, pos + 1);
 if ( ByteOrder == BYTE_ORDER_BIG_ENDIAN )
  return ord(s[0]) << 8 | ord(s[1]);
 else
  return ord(s[0]) | ord(s[1]) << 8;
}

function getbyte(blob, pos)
{
 local_var l, s;
 if ( strlen(blob) < pos + 1 )
	return NULL;
 s = substr(blob, pos, pos);
 return ord(s[0]);
}




function mkpad()
{
 local_var l;
 l = _FCT_ANON_ARGS[0];
 return crap(data:raw_string(0), length:l);
}



