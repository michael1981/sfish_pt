#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(20175);
 script_version("$Revision: 1.8 $");

 script_name(english:"VERITAS Backup Agent Detection");

 script_set_attribute(attribute:"synopsis", value:
"A backup agent is running on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a Backup Agent that uses the Network Data
Management Protocol (NDMP). 

The fact that this agent is listening on port 10000 may indicate it is
VERITAS Backup Exec or VERITAS NetBackup." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );

script_end_attributes();

 script_summary(english:"Detects VERITAS Backup Agent");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"Service detection");
 script_require_ports(10000);
 exit(0);
}

include ("global_settings.inc");
include ("misc_func.inc");
include ("sunrpc_func.inc");

global_var __stream, __stream_length, __stream_pos, __stream_error;
global_var ndmp_cid;

NDMP_MESSAGE_REQUEST = 0;
NDMP_MESSAGE_REPLY   = 1;
NDMP_CONFIG_GET_HOST_INFO     = 0x100;
NDMP_CONFIG_GET_SERVER_INFO   = 0x108;
NDMP_NOTIFY_CONNECTION_STATUS = 0x502;
NDMP_CONFIG_GET_AGENT_PROPERTIES = 0xF31B;


function xdr_getopaquestring()
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

 if (d % 4)
  __rpc_stream_pos += 4 - (d%4);

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


function ndmp_packet (code, data)
{
 local_var pack;

 pack = 
	mkdword (ndmp_cid)               + # sequence
	mkdword (0)                      + # time_stamp
	mkdword (NDMP_MESSAGE_REQUEST)   + # message type
	mkdword (code)                   + # message code
	mkdword (0)                      + # reply sequence
	mkdword (0)                      + # Error code
	data;

 return mkdword(strlen(pack) | 0x80000000) + pack;
}


function ndmp_recv (socket)
{
 local_var len, data, header;

 data = recv (socket:socket, length:4, min:4);
 if (strlen(data) < 4)
   return NULL;
 
 len = getword (blob:data, pos:2);
 data = recv (socket:socket, min:len, length:len);

 if (strlen(data) != len)
   return NULL;

 if (strlen(data) < 24)
   return NULL;

 header = NULL;
 register_stream(s:data);

 header[0] = xdr_getdword();
 header[1] = xdr_getdword();
 header[2] = xdr_getdword();
 header[3] = xdr_getdword();
 header[4] = xdr_getdword();
 header[5] = xdr_getdword();

 if (strlen(data) > 24)
   header[6] = substr (data, 24, strlen(data)-1);
 else
   header[6] = NULL;

 return header;
}


function ndmp_sendrecv(socket, code, data)
{
 local_var ret;

 data = ndmp_packet(code:code, data:data);

 send(socket:socket, data:data);
 ret = ndmp_recv(socket:socket);

 if (ret[2] != NDMP_MESSAGE_REPLY || ret[5] != 0 || ret[3] != code)
   return NULL;

 return ret[6];
}

# Main code


port = 10000;

if (!get_port_state(port))
  exit (0);

soc = open_sock_tcp (port);
if (!soc) exit (0);

req = ndmp_recv(socket:soc);
if (isnull(req))
  exit(0);

if (req[2] != NDMP_MESSAGE_REQUEST || req[3] != NDMP_NOTIFY_CONNECTION_STATUS)
  exit(0);

info = NULL;

ret = ndmp_sendrecv(socket:soc, code:NDMP_CONFIG_GET_SERVER_INFO, data:NULL);

if (!isnull(ret))
{
 register_stream(s:ret);

 error = xdr_getdword();
 vendor_name = xdr_getopaquestring();
 product_name = xdr_getopaquestring();
 revision_number = xdr_getopaquestring();

 info += string (
         "NDMP Server Info:\n\n",
         " Vendor: ", vendor_name, "\n",
         " Product: ", product_name, "\n",
         " Revision: ", revision_number, "\n\n"
         );
}

ret = ndmp_sendrecv(socket:soc, code:NDMP_CONFIG_GET_HOST_INFO, data:NULL);

if (!isnull(ret))
{
 register_stream(s:ret);

 error = xdr_getdword();
 hostname = xdr_getopaquestring();
 os_type = xdr_getopaquestring();
 os_vers = xdr_getopaquestring();
 hostid = xdr_getopaquestring();

 info += string (
         "NDMP Host Info:\n\n",
         " Hostname: ", hostname, "\n",
         " OS Type: ", os_type, "\n",
         " OS Version: ", os_vers, "\n",
         " HostID: ", hostid, "\n\n"
         );
}

data = xdr_string("nessus");

ret = ndmp_sendrecv(socket:soc, code:NDMP_CONFIG_GET_AGENT_PROPERTIES, data:data);

if (!isnull(ret))
{
 register_stream(s:ret);

 error = xdr_getdword();

 u1 = xdr_getdword();
 u2 = xdr_getdword();
 u3 = xdr_getdword();

 v1 = xdr_getdword();
 v2 = xdr_getdword();
 v3 = xdr_getdword();
 v4 = xdr_getdword();

 version = string(v1,".",v2,".",v3,".",v4);
 set_kb_item(name:"Veritas/BackupExecAgent/Version", value:version);

 info += string (
         "NDMP Agent Info:\n\n",
         " Version: ", version, "\n\n"
         );
}


security_note (port:port, extra:info);
register_service (port:port, proto:"veritas-backup-agent");
