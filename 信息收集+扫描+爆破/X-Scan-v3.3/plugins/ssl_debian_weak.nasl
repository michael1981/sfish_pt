#TRUSTED a2f6e011217b480e0b4c096ea595da8d5fb9d375b0651119d79d690102b83f85786615a0fcce51478c269de7bd8c342fea326418997010db3f0817d302ac0ef45e5d09aa56183bad3b6a6e88619b4b5597796476396ab6a59d30dd6fa5da7564ec5c8790b43133d34c6e36e4fb4101315d8bb5e9975833bb346023c050e7999d29eb93c71773ccbd29a2844b0518da9cefdbf90e98ea29c43face15706739a1d6038cca7feadbf87ce2753058caa719fcc7bfacc0f75cf635905534045aa2aa3d2436e2b35ac684b36f94116284185f39b4c4356700f4589e0093c6624c5f26701551da8697714d5a3ef4c02f95634847cb439e27fed90976a8b1fdd500407189da9d316ff727f29113e440b3a17c6f18ac62fc093870a30d30e0a603aacb0190c0db5e8c8911d0aa0a4c560f3df42fbf9895de75a464f4fa27ab23bfee42492f1060a22f83695c25a1ce21de0c69a0cfd678ff9cd2b03e4fb1991239b917a9665c1e29c08f4875abf98ef9def93dd989db860a51dd59aa315a9841d286d3ac62f01dbe15989a9f3ee0ae57fb42b0ee17a2581afb433061bc19fa67c8b47d0483a350e474313294bf6de755413f2ffeff1fda7fd83383c07cc359f96c5ba2906f42b713ca3e672f06169b4a24adff8e35908bd488309d49737f6147e6660efd504977124e090bbb5dc58892cc80f71628198a548556d9eb86db893083e3c8a44
#
# (C) Tenable Network Security, Inc.
#

if ( NASL_LEVEL < 3000 ) exit(0);


include("compat.inc");

if(description)
{
 script_id(32321);
 script_version ("1.4");

 script_cve_id("CVE-2008-0166");
 script_bugtraq_id(29179);

 name["english"] = "Debian OpenSSH/OpenSSL Package Random Number Generator Weakness (SSL check)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote SSL certificate uses a weak key." );
 script_set_attribute(attribute:"description", value:
"The remote x509 certificate on the remote SSL server has been
generated on a Debian or Ubuntu system which contains a bug in the
random number generator of its OpenSSL library. 

The problem is due to a Debian packager removing nearly all sources of
entropy in the remote version of OpenSSL. 

An attacker can easily obtain the private part of the remote key and
use this to decipher the remote session or set up a man in the middle
attack." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5d01bdab (Debian)" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f14f4224 (Ubuntu)" );
 script_set_attribute(attribute:"solution", value:
"Consider all cryptographic material generated on the remote host to be
guessable.  In particuliar, all SSH, SSL and OpenVPN key material
should be re-generated." );
 script_set_attribute(attribute:"cvss_vector", value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
	
script_end_attributes();

 
 script_summary(english:"Checks for the remote SSL public key fingerprint");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");

 if ( NASL_LEVEL >= 3200 )
  script_dependencie("find_service.nasl");
 else
  script_dependencie("find_service.nes");

 script_require_ports("Transport/SSL");
 exit(0);
}

global_var log_verbosity;

include("misc_func.inc");
include("ssl_funcs.inc");
include("kerberos_func.inc");
include("byte_func.inc");

function parse_publickey_info(pki)
{
 local_var pos, ret, ai, tmp, seq, n,e;

 pos = 0;

 ret = der_decode(data:pki, pos:pos);
 if (isnull(ret) || ret[0] != 0x30) return NULL;
 pos = ret[2];

 ret = der_parse_list(list:ret[1]);
 if (isnull(ret) || ret[0] != 2) return NULL;
 ai = der_parse_oid(oid:ret[1]);

 ret = der_decode(data:pki, pos:pos);
 if (isnull(ret) || ret[0] != 0x03) return NULL;

 # RSA only
 if (ai >!< "1.2.840.113549.1.1.1") return NULL;

 seq = der_parse_sequence (seq:substr(ret[1], 1, strlen(ret[1])-1),list:TRUE);
 if (isnull(seq) || seq[0] != 2)
   return NULL;

 n = der_parse_data(tag:0x02, data:seq[1]);
 e = der_parse_data(tag:0x02, data:seq[3]);

 tmp = NULL;
 tmp[0] = n;
 tmp[1] = e;

 return tmp;
}


function parse_tbs_certificate(cert)
{
 local_var seq, tbs, pos, i;
 local_var tlist, tmp, ret, key;

 seq = der_decode (data:cert);
 if (isnull(seq) || (seq[0] != 0x30))
   return NULL;

 tlist = tmp = NULL;
 pos = i = 0;

 while (pos < strlen(seq[1]))
 {
  ret = der_decode (data:seq[1],pos:pos);
  if (isnull(ret))
    return NULL;
  
  if (ret[0] >= 0xa0)
    tlist[ret[0] - 0xa0] = ret[1];
  else
    tmp[i++] = ret;

  pos = ret[2];
 }

 # subjectPublicKeyInfo
 ret = tmp[5];
 if (ret[0] != 0x30) return NULL;
 key = parse_publickey_info(pki:ret[1]);

 return key;
}


function  parse_der_cert(cert)
{
 local_var seq, key;

 seq = der_parse_sequence (seq:cert,list:TRUE);
 if (isnull(seq) || seq[0] != 3)
   return NULL;

 return parse_tbs_certificate(cert:seq[1]);
}


RSA_1024 = 0;
RSA_2048 = 1;

function file_read_dword(fd)
{
 local_var dword;

 dword = file_read(fp:fd, length:4);
 dword = getdword(blob:dword, pos:0);

 return dword;
}


function find_hash_list(type, first, second)
{
 local_var list, fd, i, j, main_index, sec_index, c, offset, length, len, pos, file, tmp_list;

 if (type == RSA_1024)
   file = "blacklist_ssl_rsa1024.inc";
 else if (type == RSA_2048)
   file = "blacklist_ssl_rsa2048.inc";

 if ( ! file_stat(file) ) return NULL;

 fd = file_open(name:file, mode:"r");
 if (!fd) return NULL;

 main_index = file_read_dword(fd:fd);

 for (i=0; i<main_index; i++)
 {
  c = file_read(fp:fd, length:1);
  offset = file_read_dword(fd:fd);
  length = file_read_dword(fd:fd);

  if (c == first)
  {
   file_seek(fp:fd, offset:offset);
   sec_index = file_read_dword(fd:fd);

   for (j=0; j<sec_index; j++)
   {
    c = file_read(fp:fd, length:1);
    offset = file_read_dword(fd:fd);
    length = file_read_dword(fd:fd);

    if (c == second)
    {
     file_seek(fp:fd, offset:offset);
     tmp_list = file_read(fp:fd, length:length);

     len = strlen(tmp_list);
     pos = 0;

     for (j=0; j<len; j+=10)
       list[pos++] = substr(tmp_list, j, j+9);

     break;
    }
   }

   break;
  }
 }

 file_close(fd);

 return list;
}

function is_vulnerable_fingerprint(type, fp)
{
 local_var list, i, len;

 list = find_hash_list(type:type, first:fp[0], second:fp[1]);
 if (isnull(list))
   return FALSE;

 len = max_index(list);
 
 for (i=0; i<len; i++)
   if (list[i] == fp)
     return TRUE;

 return FALSE;
}

port = get_kb_item("Transport/SSL");
if ( ! port ) exit(0);

cert = get_server_cert(port:port, encoding:"der");

key = parse_der_cert(cert:cert);
if (isnull(key)) exit(0);

key = key[0];

if (strlen(key) > 130)
  type = RSA_2048;
else
  type = RSA_1024;

while (ord(key[0]) == 0)
  key = substr(key, 1, strlen(key)-1);

mod = "Modulus=" + toupper(hexstr(key)) + '\n';

hex = substr(SHA1(mod), 0, 9);

ret = is_vulnerable_fingerprint(type:type, fp:hex);
if (ret) security_hole(port);
