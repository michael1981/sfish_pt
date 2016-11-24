# -*- Fundamental -*-
#
# 
# (C) 2007 Tenable Network Security
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
# sunrpc_func.inc 
# $Revision: 1.6 $
#


include ("byte_func.inc");

global_var __rpc_stream, __rpc_stream_length, __rpc_stream_pos, __rpc_stream_error;

AUTH_NULL  = 0;
AUTH_UNIX  = 1;
PROC_NULL  = 0;
RPCSEC_GSS = 6;


function rpc_packet (prog, vers, proc, data, credentials, verifier, udp)
{
 local_var xid, pack;

 if (isnull(credentials))
 {
  credentials[0] = AUTH_NULL;
  credentials[1] = NULL;
 }

 if (isnull(verifier))
 {
  verifier[0] = AUTH_NULL;
  verifier[1] = NULL;
 }

 xid = rand ();

 pack = 
      mkdword (xid)  + # XID
      mkdword (0)    + # Call
      mkdword (2)    + # RPC version = 2
      mkdword (prog) + # program
      mkdword (vers) + # program version
      mkdword (proc) + # Procedure
 
      # Credentials
      mkdword(credentials[0]) +
      mkdword(strlen(credentials[1])) +
      credentials[1] +

      # Verifier
      mkdword(verifier[0]) +
      mkdword(strlen(verifier[1])) +
      verifier[1] +

      # DATA
      data;

 if (isnull(udp) || udp == FALSE)
   pack = 
        mkbyte (0x80) + # Last fragment
        mkbyte (0) + mkword (strlen(pack)) + # fragment length
        pack;

 return pack;
}


function rpc_sendrecv (socket, packet, udp, timeout)
{
 local_var len, data, acc;

 send (socket:socket, data:packet);

 if (isnull(udp) || udp == FALSE)
 {
  data = recv (socket:socket, length:4, min:4, timeout:timeout);

  # does not care about multiple fragment/big packets
  len = getword (blob:data, pos:2);
  data = recv (socket:socket, min:len, length:len);

  if (strlen(data) != len)
    return NULL;
 }
 else
  data = recv (socket:socket, min:len, length:4096, timeout:timeout);

 if (strlen(data) < 24)
   return NULL;

 acc = getdword (blob:data, pos:8);
 if (acc != 0)
   return NULL;

 acc = getdword (blob:data, pos:20);
 if (acc != 0)
   return NULL;

 return substr(data, 24, strlen(data)-1);
}


function rpc_getport (socket, prog, vers, proto, udp)
{
 local_var packet, data;

 data =
	mkdword (prog) +
	mkdword (vers) +
	mkdword (proto) +
	mkdword (0);

 # portmapper : prog:100000 version:2 procedure:GETPORT(3)
 packet = rpc_packet (prog:0x186a0, vers:2, proc:3, data:data, udp:udp);

 data = rpc_sendrecv (socket:socket, packet:packet, udp:udp);
 if (isnull(data) || (strlen(data) != 4))
   return NULL;

 return getdword (blob:data, pos:0);
}


function get_rpc_port2(program, protocol, portmap, vers)
{
 local_var port, broken,soc;
 local_var portmapper_port;

 if(isnull(portmap))
 {
  port = int(get_kb_item("rpc/portmap"));
  if (port == 0)
    port = 111;
 }
 else 
  port = portmap;

 portmapper_port = port;
 	  
 broken = get_kb_item(string("/tmp/rpc/noportmap/", port));
 if (broken)
   return 0;

 soc = open_sock_udp(port);
 if (!soc)
   return 0;

 if ( isnull(vers) ) vers = 0;

 port = rpc_getport(socket:soc, prog:program, vers:vers, proto:protocol, udp:TRUE);
 close(soc);

 if(isnull(port))
 {
  set_kb_item(name:string("/tmp/rpc/noportmap/", portmapper_port), value:TRUE);
  return 0;
 }
 
 return port;
}


function register_stream(s)
{
 __rpc_stream = s;
 __rpc_stream_length = strlen(s);
 __rpc_stream_pos = 0;
 __rpc_stream_error = FALSE;
}


function xdr_getdword()
{
 local_var d;

 if ((__rpc_stream_pos + 4) > __rpc_stream_length)
 {
  __rpc_stream_error = TRUE;
  return NULL;
 }

 d = getdword(blob:__rpc_stream, pos:__rpc_stream_pos);
 __rpc_stream_pos += 4;

 return d;
}


function xdr_getstring()
{
 local_var s, d, tmps, i, len;

 d = xdr_getdword();
 if (isnull(d))
   return NULL;

 if ((__rpc_stream_pos + d) > __rpc_stream_length)
 {
  __rpc_stream_error = TRUE;
  return NULL;
 }

 tmps = substr(__rpc_stream, __rpc_stream_pos, __rpc_stream_pos+d-1);
 __rpc_stream_pos += d;

 s = NULL;
 len = strlen(tmps);
 for (i=0; i < len; i++)
 {
  if (tmps[i] == '\0')
    return s;
  else
   s += tmps[i];
 }

 return s;
}


function xdr_long()
{
 local_var l;
 l = _FCT_ANON_ARGS[0];

 return mkdword(l);
}


function xdr_string()
{
 local_var len, s;
 s = _FCT_ANON_ARGS[0];

 len = strlen(s);

 if (len % 4)
   s += crap(data:mkbyte(0), length:4-(len%4));

 return xdr_long(len) + s;
}


function xdr_auth_unix(hostname, uid, gid)
{
 local_var credentials, auth;

 auth = 
        xdr_long(rand()) +
        xdr_string(hostname) +
        xdr_long(uid) +
        xdr_long(gid) +
        xdr_long(0)   ;

 credentials = NULL;
 credentials[0] = AUTH_UNIX;
 credentials[1] = auth;

 return credentials;
}



function stream_error()
{
 return __rpc_stream_error;
}
