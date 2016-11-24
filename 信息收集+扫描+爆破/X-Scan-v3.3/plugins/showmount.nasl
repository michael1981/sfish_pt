#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(10437);
  script_version ("$Revision: 1.26 $");

  script_name(english: "NFS Share Export List");
  script_summary(english: "Gets a list of exported NFS shares");

  script_set_attribute(
    attribute:'synopsis',
    value:"The remote NFS server exports a list of shares."
  );

  script_set_attribute(
    attribute:'description',
    value:"This plugin retrieves the list of NFS exported shares."
  );

  script_set_attribute(
    attribute:'solution',
    value:"Ensure each share is intended to be exported."
  );

  script_set_attribute(
    attribute:'see_also',
    value:"http://www.tldp.org/HOWTO/NFS-HOWTO/security.html"
  );

  script_set_attribute(
    attribute:'risk_factor',
    value:'None'
  );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
  script_family(english: "RPC");
  script_dependencie("rpc_portmap.nasl");
  script_require_keys("rpc/portmap");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("sunrpc_func.inc");

function read_str()
{
  global_var	data, data_ptr, data_len;
  local_var	length, pad, s;

  if (data_ptr >= data_len) return NULL;
  length = getdword(blob: data, pos: data_ptr);
  s = substr(data, data_ptr+4, data_ptr+3+length);
  pad = length % 4;
  if (pad > 0) pad = 4 - pad; else pad = 0;
  data_ptr += 4 +  length + pad;
  return s;
}

function read_int()
{
  global_var	data, data_ptr, data_len;
  local_var	n;
  if (data_ptr >= data_len) return NULL;
  n = getdword(blob: data, pos: data_ptr);
  data_ptr += 4;
  return n;
}

list = "";
number_of_shares = 0;
RPC_MOUNTD = 100005;
port = get_rpc_port2(program: RPC_MOUNTD, protocol:IPPROTO_TCP);
soc = NULL;
if(port)
{
 soc = open_priv_sock_tcp(dport:port);
 proto = "tcp"; udp = 0;
}
else
{
 set_kb_item(name:"nfs/port/udp", value:port);
 proto = "udp";
 port = get_rpc_port2(program: RPC_MOUNTD, protocol:IPPROTO_UDP);
 udp = 1;
 if(port) soc = open_priv_sock_udp(dport:port);
}
if (! soc) exit(0);

set_kb_item(name:"nfs/proto", value:proto);

# 2 = DUMP
# 5 = EXPORT
packet = rpc_packet(prog: RPC_MOUNTD, vers: 1, proc: 0x05, udp: udp);
data = rpc_sendrecv(socket: soc, packet: packet, udp: udp);
data_ptr = 0; data_len = strlen(data);

while (read_int())	# Value follow?
{
  directory = read_str();
  groups = NULL;
  while (read_int())	# Value follow?
  {
    g = read_str();
    if (groups)
      groups = strcat(groups, ', ', g);
    else
      groups = g;
  }

  share = string(directory, " ", groups);
  list = strcat(list, share, '\n');
  set_kb_item(name:"nfs/share_acl", value:share);
  set_kb_item(name:"nfs/exportlist", value:directory);
  
  number_of_shares ++;
}


if(number_of_shares)
{
  report = strcat('Here is the export list of ', get_host_name(), ' : \n\n', list);
  security_note(port:2049, extra:report, proto:proto);
  exit(0);
}
else
{
  set_kb_item(name:"nfs/noshares", value:TRUE);
  exit(0);
}
