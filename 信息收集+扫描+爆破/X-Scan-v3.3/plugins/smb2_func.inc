#
# -*- Fundamental -*-
#
# 
# (C) 2008 Tenable Network Security
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# See the following licenses for details :
#  http://www.nessus.org/plugins/RegisteredFeed.pdf
#  http://www.nessus.org/plugins/TenableCommercial.pdf
#  http://www.nessus.org/plugins/DirectFeed.pdf
#  http://www.nessus.org/plugins/DirectFeedCommercial.pdf
#
#
# @NOGPL@
#
# smb2_func.inc
# $Revision: 1.5 $
#


global_var sha_k, null_signature;

null_signature = crap(data:'\0', length:16);


SMB2_SESSION_SETUP    = 1;
SMB2_LOGOFF           = 2;
SMB2_TREE_CONNECT     = 3;
SMB2_TREE_DISCONNECT  = 4;
SMB2_CREATE           = 5;
SMB2_CLOSE            = 6;
SMB2_FLUSH            = 7;
SMB2_READ             = 8;
SMB2_WRITE            = 9;
SMB2_LOCK             = 10;
SMB2_IOCTL            = 11;
SMB2_CANCEL           = 12;
SMB2_ECHO             = 13;
SMB2_QUERY_DIRECTORY  = 14;
SMB2_CHANGE_NOTIFY    = 15;
SMB2_QUERY_INFO       = 16;
SMB2_SET_INFO         = 17;
SMB2_OPLOCK_BREAK     = 18;

SMB2_FLAGS_SIGNED     = 8;

SMB2_0_IOCTL_IS_FSCTL  = 1;

FSCTL_PIPE_TRANSCEIVE  = 0x0011C017;

FileDirectoryInformation       = 1;
FileFullDirectoryInformation   = 2;
FileBothDirectoryInformation   = 3;
FileNamesInformation           = 0x0C;
FileIdBothDirectoryInformation = 0x25;
FileIdFullDirectoryInformation = 0x26;

SMB2_RESTART_SCANS       = 0x01;
SMB2_RETURN_SINGLE_ENTRY = 0x02;
SMB2_INDEX_SPECIFIED     = 0x04;
SMB2_REOPEN              = 0x10;


SMB2_0_INFO_FILE         = 0x01;
SMB2_0_INFO_FILESYSTEM   = 0x02;
SMB2_0_INFO_SECURITY     = 0x03;
SMB2_0_INFO_QUOTA        = 0x04;


#==================================================================#
# Section 1. Crypto                                                #
#==================================================================#



sha_k = make_list(
   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
);


#---------------------------------------------------------#
# Function    : mkbedword                                 #
# Description : Generates a raw big endian dword          #
#---------------------------------------------------------#

function mkbedword(d)
{
 return raw_string(
                (d >> 24) & 0xFF,
                (d >> 16) & 0xFF,
                (d >> 8) & 0xFF,
                d & 0xFF
                );
}


#---------------------------------------------------------#
# Function    : sha256                                    #
# Description : Computes SHA256 hash                      #
#---------------------------------------------------------#

function sha256(data)
{
 local_var len, data, pos, i, j, x;
 local_var a,b,c,d,e,f,g,h;
 local_var s0,s1,t1,t2,ch,maj,w;
 local_var h0,h1,h2,h3,h4,h5,h6,h7;

 h0 = 0x6a09e667;
 h1 = 0xbb67ae85;
 h2 = 0x3c6ef372;
 h3 = 0xa54ff53a;
 h4 = 0x510e527f;
 h5 = 0x9b05688c;
 h6 = 0x1f83d9ab;
 h7 = 0x5be0cd19;

 len = strlen(data);
 data += raw_string(0x80);

 if ((len+9) % 64)
   data = data + crap(data:'\0', length:64-((len+9)%64));

 data += mkbedword(d:0) + mkbedword(d:len*8);

 len = strlen(data);
 pos = 0;

 while (pos<len)
 {
  w = NULL;

  for (i=0; i<16; i++)
  {
    j = i*4 + pos;
    w[i] = (ord(data[j]) << 24) |
           (ord(data[j+1]) << 16) |
           (ord(data[j+2]) << 8) |
           ord(data[j+3]);
  }

  for (i=16; i<64; i++)
  {
   # ror calls are inlined for faster code
   x = w[i-15];
   s0 = ((x >>> 7) | (x << (32-7))) ^ ((x >>> 18) | (x << (32-18))) ^ (x >>> 3);
   x = w[i-2];
   s1 = ((x >>> 17) | (x << (32-17))) ^ ((x >>> 19) | (x << (32-19))) ^ (x >>> 10);
   w[i] = w[i-16] + s0 + w[i-7] + s1;
  }

  a = h0;
  b = h1;
  c = h2;
  d = h3;
  e = h4;
  f = h5;
  g = h6;
  h = h7;

  for (i=0; i<64; i++)
  {
   s0 = ((a >>> 2) | (a << (32-2))) ^ ((a >>> 13) | (a << (32-13))) ^ ((a >>> 22) | (a << (32-22)));
   maj = (a & b) ^ (a & c) ^ (b & c);
   t2 = s0 + maj;
   s1 = ((e >>> 6) | (e << (32-6))) ^ ((e >>> 11) | (e << (32-11))) ^ ((e >>> 25) | (e << (32-25)));
   ch = (e & f) ^ ((~e) & g);
   t1 = h + s1 + ch + sha_k[i] + w[i];

   h = g;
   g = f;
   f = e;
   e = d + t1;
   d = c;
   c = b;
   b = a;
   a = t1 + t2;
  }


  h0 = h0 + a;
  h1 = h1 + b;
  h2 = h2 + c;
  h3 = h3 + d;
  h4 = h4 + e;
  h5 = h5 + f;
  h6 = h6 + g;
  h7 = h7 + h;

  pos += 64;
 }

 return mkbedword(d:h0) + mkbedword(d:h1) + mkbedword(d:h2) + mkbedword(d:h3) + mkbedword(d:h4) + mkbedword(d:h5) + mkbedword(d:h6) + mkbedword(d:h7);
}


#---------------------------------------------------------#
# Function    : _HMAC_SHA256                              #
# Description : Computes HMAC-SHA256 hash                 #
#---------------------------------------------------------#

function _HMAC_SHA256(key, data)
{
 local_var i, len, ipad, opad, bsize;

 bsize = 64;

 ipad = crap(data:'6', length:bsize);
 opad = crap(data:'\\', length:bsize);

 if (strlen(key) > bsize)
   key = sha256(data:key);

 len = strlen(key);

 for (i=0; i<len; i++)
 {
  ipad[i] = raw_string(ord(key[i]) ^ 0x36);
  opad[i] = raw_string(ord(key[i]) ^ 0x5C);
 }

 return sha256(data:opad + sha256(data:ipad + data));
}


#==================================================================#
# Section 2. Utilities                                             #
#==================================================================#


#---------------------------------------------------------#
# Function    : mklist                                    #
# Description : Generates a list                          #
#---------------------------------------------------------#

function mklist()
{
 local_var ret;
 local_var i, l;

 l = max_index (_FCT_ANON_ARGS);

 if ( defined_func("fill_list") )
  ret  = fill_list(length:l, value:0);

 for (i=0 ; i<l ; i++)
   ret[i] = _FCT_ANON_ARGS[i];

 return ret;
}


#---------------------------------------------------------#
# Function    : raw_qword                                 #
# Description : Converts a DWORD to a raw little endian   #
#               QWORD                                     #
#---------------------------------------------------------#

function raw_qword(q)
{
 return raw_dword(d:q) + raw_dword(d:0);
}


#---------------------------------------------------------#
# Function    : get_qword                                 #
# Description : Reads a QWORD in a buffer and converts it #
#               to a DWORD                                #
#---------------------------------------------------------#

function get_qword(blob, pos)
{
 return get_dword(blob:blob, pos:pos);
}



#==================================================================#
# Section 3. SMB2 Code                                             #
#==================================================================#


#---------------------------------------------------------#
# Function    : smb2_header                               #
# Description : Returns an encoded SMB header without     #
#               the signature                             #
#---------------------------------------------------------#

function smb2_header(command, status, flags)
{
 local_var header, fl;

 if (isnull(flags))
   flags = 0;

 header = 
        '\xFESMB'                       + # ProtocolId
        raw_word(w:64)                  + # StructureSize
        raw_word(w:0)                   + # Epoch
        raw_dword(d:status)             + # Status
        raw_word(w:command)             + # Command
        raw_word(w:126)                 + # Credits
        raw_dword(d:flags)              + # Flags
        raw_dword(d:0)                  + # NextCommand
        raw_qword(q:session_get_messageid())  + # MessageId
        raw_dword(d:session_get_pid())  + # ProcessId
        raw_dword(d:session_get_tid())  + # TreeId
        session_get_sid()               ; # SessionId

 return header;
}


#---------------------------------------------------------#
# Function    : smb_decode_header                         #
# Description : Decodes a SMB2 header                     #
#---------------------------------------------------------#

function smb_decode_header(header)
{
 local_var ret;

 ret = NULL;

 ret[0] = substr(header, 0, 3);
 ret[1] = get_word(blob:header, pos:4);
 ret[2] = get_word(blob:header, pos:6);
 ret[3] = get_dword(blob:header, pos:8);
 ret[4] = get_word(blob:header, pos:12);
 ret[5] = get_word(blob:header, pos:14);
 ret[6] = get_word(blob:header, pos:16);
 ret[7] = get_word(blob:header, pos:20);
 ret[8] = get_qword(blob:header, pos:24);
 ret[9] = get_dword(blob:header, pos:32);
 ret[10] = get_dword(blob:header, pos:36);
 ret[11] = substr(header, 40, 47);
 ret[12] = substr(header, 48, 63);

 return ret;
}


#---------------------------------------------------------#
# Function    : decode_smb2                               #
# Description : Decodes a SMB2 packet                     #
#---------------------------------------------------------#

function decode_smb2(data)
{
 local_var header, data, length;
 local_var key, tohash, hash;

 length = strlen(data);

 header = smb_decode_header(header:substr(data, 0, 63));

 key = session_get_mackey();
 if (key && header[3] != STATUS_PENDING)
 {
  tohash = substr(data, 0, 47) + null_signature + substr(data, 64, length-1);
  hash = _HMAC_SHA256(key:key, data:tohash);

  if (substr(hash, 0, 15) != header[12])
    return NULL;
 }

 if (length > 64)
   data = substr(data, 64, length-1);
 else
   data = NULL;

 return mklist(header, data);
}


#---------------------------------------------------------#
# Function    : smb2_recv                                 #
# Description : Receives and decodes a SMB2 packet        #
#---------------------------------------------------------#

function smb2_recv ()
{
 local_var socket, timeout, length, trailer, ret, header;

 socket = session_get_socket ();
 timeout = session_get_timeout ();

 length = recv(socket:socket, length:4, min:4, timeout:timeout);
 if (strlen(length) != 4)
   return NULL;
   
 length = 65535 * ord(length[1]) +
          256 * ord(length[2]) +
          ord(length[3]);
   
 if (length < 64)
   return NULL;

 if (length > 100000)
   length = 100000;

 trailer = recv(socket:socket, length:length, min:length, timeout:timeout);
 if (strlen(trailer) < length )
   return NULL;

 ret = decode_smb2(data:trailer);
 if (isnull(ret))
   return NULL;

 header = ret[0];

 # the server must not send anything before the reply as we are not asynchronous
 if (header[3] == STATUS_PENDING)
   return smb2_recv();

 return ret;
}


#---------------------------------------------------------#
# Function    : smb2_sendrecv                             #
# Description : Sends and receives a SMB2 packet          #
#---------------------------------------------------------#

function smb2_sendrecv(command, data)
{
 local_var header, netbios, socket, length, signature, key;

 key = session_get_mackey();
 if (key)
 {
  header = smb2_header(command:command, status:STATUS_SUCCESS, flags:SMB2_FLAGS_SIGNED);
  signature = _HMAC_SHA256(key:key, data:header+null_signature+data);
  header = header + substr(signature,0,15);
 }
 else
   header = smb2_header(command:command, status:STATUS_SUCCESS) + null_signature;

 length = strlen(header) + strlen(data);

 netbios = netbios_header (type:0, length:length) +
           header + data;

 socket = session_get_socket();
 send (socket:socket, data:netbios);
 
 if (session_get_mackey())
   session_increase_sequencenumber();

 return smb2_recv ();
}


#---------------------------------------------------------#
# Function    : smb2_session_setup                        #
# Description : Performs a SMB2 session setup             #
#---------------------------------------------------------#

function smb2_session_setup(login, password, hash, domain)
{
 local_var data, ret, securityblob, header, length;
 local_var challenge, d_name, flags, mackey, secmode;

 securityblob = ntlmssp_negotiate_securityblob ();

 data =
      raw_word(w:25)                    + # StructureSize
      raw_byte(b:0)                     + # VcNumber
      raw_byte(b:1)                     + # SecurityMode
      raw_dword(d:0)                    + # Capabilities
      raw_dword(d:0)                    + # Channel
      raw_word(w:0x58)                  + # SecurityBufferOffset
      raw_word(w:strlen(securityblob))  + # SecurityBufferLength
      raw_qword(q:0)                    + # PreviousSessionId
      securityblob                      ; # Buffer

 ret = smb2_sendrecv(command:SMB2_SESSION_SETUP, data:data);
 if (isnull(ret))
   return NULL;

 header = ret[0];
 if (header[3] != STATUS_MORE_PROCESSING_REQUIRED)
   return NULL;

 session_set_sid(sid:header[11]);

 data = ret[1];
 if (strlen(data) < 8)
   return NULL;

 length = get_word(blob:data, pos:6);
 if (strlen(data) < (length+8))
   return NULL;

 securityblob = substr(data, 8, length+7);

 challenge = ntlmssp_parse_challenge (data:securityblob);
 if (isnull(challenge))
   return NULL; 

 session_set_addrlist(addrlist:challenge[2]);

 d_name = get_string2 (blob:challenge[1], pos:0, len:strlen(challenge[1]));
 challenge = challenge[0];

 session_set_host_info (domain:d_name, os:NULL, lan:NULL);

 if (login)
 {
  if (password)
    password = cstring (string:password, _null:1);
  login = cstring (string:login, _null:1);
  domain = cstring (string:domain, _null:1);  
 }
 else
 {
  login = password = domain = hash = NULL;
 }

 securityblob = ntlmssp_auth_securityblob (password:password,login:login,hash:hash,domain:domain,challenge:challenge);
 if (isnull(securityblob))
   return NULL;

 mackey = securityblob[0];
 securityblob = securityblob[1];

 secmode = session_get_secmode();

 data =
      raw_word(w:25)                    + # StructureSize
      raw_byte(b:0)                     + # VcNumber
      raw_byte(b:secmode)               + # SecurityMode
      raw_dword(d:0)                    + # Capabilities
      raw_dword(d:0)                    + # Channel
      raw_word(w:0x58)                  + # SecurityBufferOffset
      raw_word(w:strlen(securityblob))  + # SecurityBufferLength
      raw_qword(q:0)                    + # PreviousSessionId
      securityblob                      ; # Buffer

 ret = smb2_sendrecv(command:SMB2_SESSION_SETUP, data:data);
 if (isnull(ret))
   return NULL;
 
 header = ret[0];
 if (header[3] != STATUS_SUCCESS)
   return NULL;

 if (secmode)
   session_set_mackey(key:mackey);

 data = ret[1];
 if (strlen(data) < 8)
   return NULL;

 length = get_word(blob:data, pos:6);
 if (strlen(data) < (length+8))
   return NULL;

 securityblob = substr(data, 8, 8+length-1);

 flags = get_word(blob:data, pos:6);

 challenge = ntlmssp_parse_response (data:securityblob);
 if (isnull(challenge) || (challenge != 0)) # Accept Completed
   return NULL;

 return flags;
}


#---------------------------------------------------------#
# Function    : smb2_tree_connect                         #
# Description : Performs a SMB2 tree connect              #
#---------------------------------------------------------#

function smb2_tree_connect(path)
{
 local_var data, ret, header;

 path = cstring (string:"\\", _null:1) + cstring (string:session_get_hostname(), _null:1) + cstring (string:"\", _null:1) + cstring (string:path, _null:1);

 data =
      raw_word(w:9)                     + # StructureSize
      raw_word(w:0)                     + # Reserved
      raw_word(w:0x48)                  + # PathOffset
      raw_word(w:strlen(path))          + # PathLength
      path                              ; # Buffer

 ret = smb2_sendrecv(command:SMB2_TREE_CONNECT, data:data);
 if (isnull(ret))
   return NULL;

 header = ret[0];
 if (header[3] != STATUS_SUCCESS)
   return NULL;

 session_set_tid(tid:header[10]);

 data = ret[1];
 if (strlen(data) != 16)
   return NULL;

 ret = NULL;
 ret[0] = get_word(blob:data, pos:0);   # StructureSize
 ret[1] = get_byte(blob:data, pos:2);   # ShareType
 ret[2] = get_byte(blob:data, pos:3);   # Reserved
 ret[3] = get_dword(blob:data, pos:4);  # ShareFlags
 ret[4] = get_dword(blob:data, pos:8);  # Capabilities
 ret[5] = get_dword(blob:data, pos:12); # MaximalAccess

 return ret;
}


#---------------------------------------------------------#
# Function    : smb2_connect                              #
# Description : Performs a SMB2 connect                   #
#---------------------------------------------------------#

function smb2_create(name, desired_access, flags_attributes, share_mode, create_disposition, create_options)
{
 local_var data, ret, header;

 if (name && (name[0] == '\\'))
   name = substr(name, 1, strlen(name)-1);

 name = cstring(string:name, _null:1);

 data =
      raw_word(w:0x39)                  + # StructureSize
      raw_byte(b:0)                     + # SecurityFlags
      raw_byte(b:0)                     + # RequestedOplockLevel
      raw_dword(d:2)                    + # ImpersonationLevel
      raw_qword(q:0)                    + # SmbCreateFlags
      raw_qword(q:0)                    + # Reserved
      raw_dword(d:desired_access)       + # DesiredAccess
      raw_dword(d:flags_attributes)     + # FileAttributes
      raw_dword(d:share_mode)           + # ShareAccess
      raw_dword(d:create_disposition)   + # CreateDisposition
      raw_dword(d:create_options)       + # CreateOptions
      raw_word(w:0x78)                  + # NameOffset
      raw_word(w:strlen(name))          + # NameLength
      raw_dword(d:0)                    + # CreateContextsOffset
      raw_dword(d:0)                    + # CreateContextsLength
      name                              ; # Buffer

 ret = smb2_sendrecv(command:SMB2_CREATE, data:data);
 if (isnull(ret))
   return NULL;

 header = ret[0];
 if (header[3] != STATUS_SUCCESS)
   return NULL;

 data = ret[1];
 if (strlen(data) != 88)
   return NULL;
 
 ret = NULL;
 ret[0] = substr(data, 64, 79)          ; # FileId
 ret[1] = substr(data, 48, 63)          ; # EndofFile

 return ret;
}


#---------------------------------------------------------#
# Function    : smb2_write                                #
# Description : Writes to a pipe/file                     #
#---------------------------------------------------------#

function smb2_write(fid, offset, mode, data)
{
 local_var ret, header;

 data =
      raw_word(w:0x31)                  + # StructureSize
      raw_word(w:0x70)                  + # DataOffset
      raw_dword(d:strlen(data))         + # Length
      raw_qword(q:offset)               + # Offset
      fid                               + # FileId
      raw_dword(d:0)                    + # Channel
      raw_dword(d:0)                    + # RemainingBytes
      raw_word(w:0)                     + # WriteChannelInfoOffset
      raw_word(w:0)                     + # WriteChannelInfoLength
      raw_dword(d:0)                    + # Flags
      data                              ; # Buffer

 ret = smb2_sendrecv(command:SMB2_WRITE, data:data);
 if (isnull(ret))
   return NULL;

 header = ret[0];
 if (header[3] != STATUS_SUCCESS)
   return NULL;

 data = ret[1];
 if (strlen(data) < 16)
   return NULL;
 
 ret = NULL;
 ret[0] = get_word(blob:data, pos:0)    ; # StructureSize
 ret[1] = get_word(blob:data, pos:2)    ; # Reserved
 ret[2] = get_dword(blob:data, pos:4)   ; # Count
 ret[3] = get_dword(blob:data, pos:8)   ; # Remaining
 ret[4] = get_word(blob:data, pos:12)   ; # WriteChannelInfoOffset
 ret[5] = get_word(blob:data, pos:14)   ; # WriteChannelInfoLength

 return ret;
}


#---------------------------------------------------------#
# Function    : smb2_read                                 #
# Description : Reads from a pipe/file                    #
#---------------------------------------------------------#

function smb2_read(fid, offset, length)
{
 local_var data, ret, header, pos;

 data =
      raw_word(w:0x31)                  + # StructureSize
      raw_byte(b:0)                     + # Padding
      raw_byte(b:0)                     + # Reserved
      raw_dword(d:length)               + # Length
      raw_qword(q:offset)               + # Offset
      fid                               + # FileId
      raw_dword(d:0)                    + # MininumCount
      raw_dword(d:0)                    + # Channel
      raw_dword(d:0)                    + # RemainingBytes
      raw_word(w:0)                     + # WriteChannelInfoOffset
      raw_word(w:0)                     + # WriteChannelInfoLength
      raw_byte(b:0)                     ;

 ret = smb2_sendrecv(command:SMB2_READ, data:data);
 if (isnull(ret))
   return NULL;

 header = ret[0];
 if (header[3] != STATUS_SUCCESS && header[3] != STATUS_BUFFER_OVERFLOW)
   return NULL;

 data = ret[1];
 if (strlen(data) < 16)
   return NULL;

 ret = NULL;
 ret[0] = get_word(blob:data, pos:0)    ; # StructureSize
 ret[1] = get_byte(blob:data, pos:2)    ; # DataOffset
 ret[2] = get_byte(blob:data, pos:3)    ; # Reserved
 ret[3] = get_dword(blob:data, pos:4)   ; # DataLength
 ret[4] = get_dword(blob:data, pos:8)   ; # DataRemaining 
 ret[5] = get_dword(blob:data, pos:12)  ; # Reserved2

 if (ret[3] > 0)
 {
  pos = ret[1] - 0x40;
  ret[6] = substr(data, pos, pos+ret[3]-1);
 }
 else
   ret[6] = NULL;

 return ret[6];
}


#---------------------------------------------------------#
# Function    : smb2_ioctl                                #
# Description : Performs a IOCTL operation on the file    #
#               descriptor                                #
#---------------------------------------------------------#

function smb2_ioctl(fid, code, data)
{
 local_var data, ret, header, type, pos;

 if (code == FSCTL_PIPE_TRANSCEIVE)
   type = SMB2_0_IOCTL_IS_FSCTL;

 data =
      raw_word(w:0x39)                  + # StructureSize
      raw_word(w:0)                     + # Reserved
      raw_dword(d:code)                 + # CtlCode
      fid                               + # FileId
      raw_dword(d:0x78)                 + # InputOffset
      raw_dword(d:strlen(data))         + # InputCount
      raw_dword(d:0)                    + # MaxInputResponse
      raw_dword(d:0x78)                 + # OutputOffset
      raw_dword(d:0)                    + # OutputCount
      raw_dword(d:65535)                + # MaxOutputResponse
      raw_dword(d:type)                 + # Flags
      raw_dword(d:0)                    + # Reserved2
      data                              ; # Buffer

 ret = smb2_sendrecv(command:SMB2_IOCTL, data:data);
 if (isnull(ret))
   return NULL;

 header = ret[0];
 if (header[3] != STATUS_SUCCESS)
   return NULL;

 data = ret[1];
 if (strlen(data) < 48)
   return NULL;
 
 ret = NULL;
 ret[0] = get_word(blob:data, pos:0)    ; # StructureSize
 ret[1] = get_word(blob:data, pos:2)    ; # Reserved
 ret[2] = get_dword(blob:data, pos:4)   ; # CtlCode
 ret[3] = substr(data, 8, 23)           ; # FileId
 ret[4] = get_dword(blob:data, pos:24)  ; # InputOffset
 ret[5] = get_dword(blob:data, pos:28)  ; # InputCount
 ret[6] = get_dword(blob:data, pos:32)  ; # OutputOffset
 ret[7] = get_dword(blob:data, pos:36)  ; # OutputCount
 ret[8] = get_dword(blob:data, pos:40)  ; # Flags
 ret[9] = get_dword(blob:data, pos:44)  ; # Reserved2

 if (ret[5] > 0)
 {
  pos = ret[4] - 0x40;
  ret[10] = substr(data, pos, pos+ret[5]-1);
 }
 else
  ret[10] = NULL;

 if (ret[7] > 0)
 {
  pos = ret[6] - 0x40;
  ret[11] = substr(data, pos, pos+ret[7]-1);
 }
 else
  ret[11] = NULL;

 return ret;
}


#---------------------------------------------------------#
# Function    : smb2_close                                #
# Description : Closes the file descriptor                #
#---------------------------------------------------------#

function smb2_close(fid)
{
 local_var data, ret, header;

 data =
      raw_word(w:24)                    + # StructureSize
      raw_word(w:0)                     + # Flags
      raw_dword(d:0)                    + # Reserved
      fid                               ; # FileId

 ret = smb2_sendrecv(command:SMB2_CLOSE, data:data);
 if (isnull(ret))
   return NULL;

 header = ret[0];
 if (header[3] != STATUS_SUCCESS)
   return NULL;

 data = ret[1];
 if (strlen(data) < 60)
   return NULL;

 ret = NULL;
 ret[0] = get_word(blob:data, pos:0);    # StructureSize
 ret[1] = get_byte(blob:data, pos:2);    # Flags
 ret[2] = get_dword(blob:data, pos:4);   # Reserved
 ret[3] = get_qword(blob:data, pos:8);   # CreationTime
 ret[4] = get_qword(blob:data, pos:16);  # LastAccessTime
 ret[5] = get_qword(blob:data, pos:24);  # LastWriteTime
 ret[6] = get_qword(blob:data, pos:32);  # ChangeTime
 ret[7] = get_qword(blob:data, pos:40);  # AllocationSize
 ret[8] = get_qword(blob:data, pos:48);  # EndofFile
 ret[9] = get_dword(blob:data, pos:56);  # FileAttributes

 return ret;
}


#---------------------------------------------------------#
# Function    : smb2_tree_disconnect                      #
# Description : Disconnect from the current tree          #
#---------------------------------------------------------#

function smb2_tree_disconnect()
{
 local_var data, ret, header, tid;

 tid = session_get_tid ();
 if (isnull(tid))
   return 1;

 data =
      raw_word(w:4)                     + # StructureSize
      raw_word(w:0)                     ; # Reserved

 ret = smb2_sendrecv(command:SMB2_TREE_DISCONNECT, data:data);
 if (isnull(ret))
   return NULL;

 header = ret[0];
 if (header[3] != STATUS_SUCCESS)
   return NULL;

 data = ret[1];
 if (strlen(data) < 4)
   return NULL;

 ret = NULL;
 ret[0] = get_word(blob:data, pos:0);   # StructureSize
 ret[1] = get_byte(blob:data, pos:2);   # Reserved

 session_set_tid(tid:NULL);

 return ret;
}


#---------------------------------------------------------#
# Function    : smb2_logoff                               #
# Description : Logs off                                  #
#---------------------------------------------------------#

function smb2_logoff()
{
 local_var data, ret, header;

 data =
      raw_word(w:4)                     + # StructureSize
      raw_word(w:0)                     ; # Reserved

 ret = smb2_sendrecv(command:SMB2_LOGOFF, data:data);
 if (isnull(ret))
   return NULL;

 header = ret[0];
 if (header[3] != STATUS_SUCCESS)
   return NULL;

 data = ret[1];
 if (strlen(data) < 4)
   return NULL;

 ret = NULL;
 ret[0] = get_word(blob:data, pos:0);   # StructureSize
 ret[1] = get_byte(blob:data, pos:2);   # Reserved

 return ret;
}


#---------------------------------------------------------#
# Function    : decode_file_directory_info                #
# Description : Decodes a FileDirectoryInformation        #
#               structure                                 #
#---------------------------------------------------------#

function decode_file_directory_info(data)
{
 local_var nextoffset, pos, ret, i, file, len;

 if (!data) return NULL;

 len = strlen(data);
 pos = 0;
 i = 0;
 ret = NULL;

 while (pos < len)
 {
  nextoffset = get_dword(blob:data, pos:pos);
  file = NULL;

  file[0] = get_dword(blob:data, pos:pos+4);   # FileIndex
  file[1] = get_qword(blob:data, pos:pos+8);   # CreationTime
  file[2] = get_qword(blob:data, pos:pos+16);  # LastAccessTime
  file[3] = get_qword(blob:data, pos:pos+24);  # LastWriteTime
  file[4] = get_qword(blob:data, pos:pos+32);  # ChangeTime
  file[5] = get_qword(blob:data, pos:pos+40);  # EndOfFile
  file[6] = get_qword(blob:data, pos:pos+48);  # AllocationSize
  file[7] = get_dword(blob:data, pos:pos+56);  # FileAttributes
  file[8] = get_dword(blob:data, pos:pos+60);  # FileNameLength
  file[9] = get_string2 (blob:data, pos:pos+64, len:file[8]);

  pos = pos + nextoffset;
  ret[i++] = file; 

  if (nextoffset == 0)
    break;
 }

 return ret;
}


#---------------------------------------------------------#
# Function    : smb2_query_directory                      #
# Description : Queries directory information             #
#---------------------------------------------------------#

function smb2_query_directory(flags, index, pattern, id)
{
 local_var data, ret, header;

 pattern = cstring(string:pattern, _null:1);
 
 data =
      raw_word(w:33)                       + # StructureSize
      raw_byte(b:FileDirectoryInformation) + # FileInformationClass
      raw_byte(b:flags)                    + # Flags
      raw_dword(d:index)                   + # FileIndex
      id                                   + # FileId
      raw_word(w:0x60)                     + # FileNameOffset
      raw_word(w:strlen(pattern))          + # FileNameLength
      raw_dword(d:4096)                    + # OutputBufferLength
      pattern;

 ret = smb2_sendrecv(command:SMB2_QUERY_DIRECTORY, data:data);
 if (isnull(ret))
   return NULL;

 header = ret[0];
 if (header[3] != STATUS_SUCCESS)
   return NULL;

 data = ret[1];
 if (strlen(data) < 8)
   return NULL;

 ret = NULL;
 ret[0] = get_word(blob:data, pos:0);   # StructureSize
 ret[1] = get_byte(blob:data, pos:2);   # OutputBufferOffset 
 ret[2] = get_dword(blob:data, pos:4);  # OutputBufferLength

 if (strlen(data) < (8+ret[2]))
   return NULL;

 ret[3] = substr(data, 8, 8+ret[2]-1);

 return decode_file_directory_info(data:ret[3]);
}


#---------------------------------------------------------#
# Function    : smb2_query_info                           #
# Description : Queries FID information                   #
#---------------------------------------------------------#

function smb2_query_info(type, class, info, id)
{
 local_var data, ret, header;

 pattern = cstring(string:pattern, _null:1);
 
 data =
      raw_word(w:41)                       + # StructureSize
      raw_byte(b:type)                     + # InfoType
      raw_byte(b:class)                    + # FileInfoClass
      raw_dword(d:0)                       + # OutputBufferLength
      raw_word(w:0)                        + # InputBufferOffset
      raw_word(w:0)                        + # Reserved
      raw_dword(d:0)                       + # InputBufferLength
      raw_dword(d:info)                    + # AdditionalInformation
      raw_dword(d:0)                       + # Flags
      id                                   ; # FileId

 ret = smb2_sendrecv(command:SMB2_QUERY_INFO, data:data);
 if (isnull(ret))
   return NULL;

 header = ret[0];
 if (header[3] != STATUS_BUFFER_TOO_SMALL)
   return NULL;

 data = ret[1];
 if (strlen(data) < 12)
   return NULL;

 olen = get_dword(blob:data, pos:8);

 data =
      raw_word(w:41)                       + # StructureSize
      raw_byte(b:type)                     + # InfoType
      raw_byte(b:class)                    + # FileInfoClass
      raw_dword(d:olen)                    + # OutputBufferLength
      raw_word(w:0)                        + # InputBufferOffset
      raw_word(w:0)                        + # Reserved
      raw_dword(d:0)                       + # InputBufferLength
      raw_dword(d:info)                    + # AdditionalInformation
      raw_dword(d:0)                       + # Flags
      id                                   ; # FileId

 ret = smb2_sendrecv(command:SMB2_QUERY_INFO, data:data);
 if (isnull(ret))
   return NULL;

 header = ret[0];
 if (header[3] != STATUS_SUCCESS)
   return NULL;

 data = ret[1];
 if (strlen(data) < 8)
   return NULL;

 ret = NULL;
 ret[0] = get_word(blob:data, pos:0);   # StructureSize
 ret[1] = get_byte(blob:data, pos:2);   # OutputBufferOffset 
 ret[2] = get_dword(blob:data, pos:4);  # OutputBufferLength

 if (strlen(data) < (8+ret[2]))
   return NULL;

 ret[3] = substr(data, 8, 8+ret[2]-1);

 return ret;
}


#---------------------------------------------------------#
# Function    : smb2_negotiate                            #
# Description : Parses SMB2 negotiate response            #
#---------------------------------------------------------#

function smb2_negotiate(data)
{
 local_var ret, header, data, pos;

 ret = decode_smb2(data:data);
 
 header = ret[0];
 if (header[3] != STATUS_SUCCESS)
   return NULL;

 data = ret[1];
 if (strlen(data) < 64)
   return NULL;

 ret = NULL;
 ret[0] = get_word(blob:data, pos:0);     # StructureSize
 ret[1] = get_word(blob:data, pos:2);     # SecurityMode
 ret[2] = get_word(blob:data, pos:4);     # DialectRevision
 ret[3] = get_word(blob:data, pos:6);     # Reserved
 ret[4] = substr(data, 8, 23);            # ServerGuid
 ret[5] = get_dword(blob:data, pos:24);   # Capabilities
 ret[6] = get_dword(blob:data, pos:28);   # MaxTransactSize
 ret[7] = get_dword(blob:data, pos:32);   # MaxReadSize
 ret[8] = get_dword(blob:data, pos:36);   # MaxWriteSize
 ret[9] = get_qword(blob:data, pos:40);   # SystemTime
 ret[10] = get_qword(blob:data, pos:48);  # ServerStartTime
 ret[11] = get_word(blob:data, pos:56);   # SecurityBufferOffset
 ret[12] = get_word(blob:data, pos:58);   # SecurityBufferLength
 ret[13] = get_dword(blob:data, pos:60);  # Reserved2

 if (ret[12] > 0)
 {
  pos = ret[11] - 0x40;
  ret[14] = substr(data, pos, pos+ret[12]-1);
 }
 else
  ret[14] = NULL;

 return ret;
}


#---------------------------------------------------------#
# Function    : smb2_login                                #
# Description : Logs in using SMB2 protocol               #
#---------------------------------------------------------#

function smb2_login (negotiate,login,password,domain,lm_hash,ntlm_hash)
{
 local_var ret;
 local_var SecurityMode, Capabilities, SecurityBlob, MaxBufferSize;
 local_var spnego, michlist, host, realm, Extended;
 local_var hash;

 if (!isnull(ntlm_hash))
   hash = ntlm_hash;
 else
   hash = NULL;

 ret = smb2_negotiate(data:negotiate);
 if (isnull(ret))
   return NULL;

 session_set_smb2(flag:TRUE);
 session_set_unicode(unicode:1);

 SecurityMode = ret[1];
 Capabilities = ret[5];
 SecurityBlob = ret[14];
 MaxBufferSize = ret[8];

 spnego = der_parse_spnego_init (sdata:SecurityBlob);
 if (!isnull (spnego) && (spnego[3] != NULL))
 {
  michlist = spnego[3];
  host = ereg_replace (pattern:"(.*)\$@.*", string:michlist, replace:"\1");
  realm = ereg_replace (pattern:".*\$@(.*)", string:michlist, replace:"\1");
  Extended = 2; # Kerberos
 }
 else
   Extended = 1;

 if (SecurityMode & 2)
   session_set_secmode(mode:SecurityMode);

 if (Capabilities & CAP_EXTENDED_SECURITY)
   session_add_flags2 (flag:SMB_FLAGS2_EXTENDED_SECURITY);

 session_set_server_max_size (size:MaxBufferSize);
 if (MaxBufferSize > (session_get_buffersize() - 0x100))
   session_set_buffersize(size:MaxBufferSize+0x100);

 ret = smb2_session_setup(login:login, password:password, hash:hash, domain:domain);
 if (isnull (ret))
   return 0;
 else 
   return 1;
}

