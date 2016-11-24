#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
  script_id(11111);
  script_version("$Revision: 1.22 $");

  script_name(english:"RPC Services Enumeration");

 script_set_attribute(attribute:"synopsis", value:
"An ONC RPC service is running on the remote host." );
 script_set_attribute(attribute:"description", value:
"By sending a DUMP request to the portmapper, it was possible to
enumerate the ONC RPC services running on the remote port.  Using this
information, it is possible to connect and bind to each service by
sending an RPC request to the remote port." );
 script_set_attribute(attribute:"risk_factor", value: "None" );
 script_set_attribute(attribute:"solution", value: "n/a" );
script_end_attributes();

  script_summary(english:"Enumerates the remote RPC services");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
  script_family(english: "Service detection");
  script_dependencies("rpc_portmap.nasl");
  script_require_ports("rpc/portmap");
  exit (0);
}


include("global_settings.inc");
include("misc_func.inc");
include ("sunrpc_func.inc");

# we use 2 lists to speed up the search / service registering
global_var tcp_rpc_server, udp_rpc_server, rpc_info;

rpc_info = NULL;
rpc_info["100000"] = "portmapper";
rpc_info["100001"] = "rstatd";
rpc_info["100002"] = "rusersd";
rpc_info["100003"] = "nfs";
rpc_info["100004"] = "ypserv";
rpc_info["100005"] = "mountd";
rpc_info["100007"] = "ypbind";
rpc_info["100008"] = "walld";
rpc_info["100009"] = "yppasswdd";
rpc_info["100010"] = "etherstatd";
rpc_info["100011"] = "rquotad";
rpc_info["100012"] = "sprayd";
rpc_info["100013"] = "3270_mapper";
rpc_info["100014"] = "rje_mapper";
rpc_info["100015"] = "selection_svc";
rpc_info["100016"] = "database_svc";
rpc_info["100017"] = "rexd";
rpc_info["100018"] = "alis";
rpc_info["100019"] = "sched";
rpc_info["100020"] = "llockmgr";
rpc_info["100021"] = "nlockmgr";
rpc_info["100022"] = "x25.inr";
rpc_info["100023"] = "statmon";
rpc_info["100024"] = "status";
rpc_info["100026"] = "bootparam";
rpc_info["100028"] = "ypupdated";
rpc_info["100029"] = "keyserv";
rpc_info["100033"] = "sunlink_mapper";
rpc_info["100037"] = "tfsd";
rpc_info["100038"] = "nsed";
rpc_info["100039"] = "nsemntd";
rpc_info["100043"] = "showfhd";
rpc_info["100055"] = "ioadmd";
rpc_info["100062"] = "NETlicense";
rpc_info["100065"] = "sunisamd";
rpc_info["100066"] = "debug_svc";
rpc_info["100068"] = "cmsd";
rpc_info["100069"] = "ypxfrd";
rpc_info["100071"] = "bugtraqd";
rpc_info["100078"] = "kerbd";
rpc_info["100083"] = "ttdbserverd";
rpc_info["100101"] = "event";
rpc_info["100102"] = "logger";
rpc_info["100104"] = "sync";
rpc_info["100107"] = "hostperf";
rpc_info["100109"] = "activity";
rpc_info["100112"] = "hostmem";
rpc_info["100113"] = "sample";
rpc_info["100114"] = "x25";
rpc_info["100115"] = "ping";
rpc_info["100116"] = "rpcnfs";
rpc_info["100117"] = "hostif";
rpc_info["100118"] = "etherif";
rpc_info["100120"] = "iproutes";
rpc_info["100121"] = "layers";
rpc_info["100122"] = "snmp";
rpc_info["100123"] = "traffic";
rpc_info["100133"] = "nsm_addrand";
rpc_info["100221"] = "kcms_server";
rpc_info["100227"] = "nfs_acl";
rpc_info["100229"] = "metad";
rpc_info["100230"] = "metamhd";
rpc_info["100232"] = "sadmind";
rpc_info["100233"] = "ufsd";
rpc_info["100242"] = "metamedd";
rpc_info["100249"] = "snmpXdmid";
rpc_info["100300"] = "nisd";
rpc_info["100303"] = "nispasswd";
rpc_info["100422"] = "metamedd";
rpc_info["150001"] = "pcnfsd";
rpc_info["300019"] = "amd";
rpc_info["300598"] = "dmispd";
rpc_info["390103"] = "nsrd";
rpc_info["390104"] = "nsrmmd";
rpc_info["390105"] = "nsrindexd";
rpc_info["390107"] = "nsrmmdbd";
rpc_info["390110"] = "nsrjb";
rpc_info["390113"] = "nsrexec";
rpc_info["390400"] = "nsrnotd";
rpc_info["391002"] = "sgi_fam";
rpc_info["200100001"] = "netinfobind";
rpc_info["545580417"] = "bwnfsd";
rpc_info["600100069"] = "fypxfrd";
rpc_info["805306368"] = "dmispd";
rpc_info["1073741824"] = "fmproduct";
rpc_info["1289637086"] = "dtcm";


function add_rpc_server (p, v, proto, port)
{
 local_var list, entry, pos;

 entry = string(port);

 if (proto == IPPROTO_TCP)
 {
  if (isnull(tcp_rpc_server[entry]))
  {
   list = NULL;
   pos = 0;
  }
  else
  {
   list = tcp_rpc_server[entry];
   pos = max_index(list);
  }

  list[pos] = make_list(p, v);
  tcp_rpc_server[entry] = list;
 }
 else if (proto == IPPROTO_UDP)
 {
  if (isnull(udp_rpc_server[entry]))
  {
   list = NULL;
   pos = 0;
  }
  else
  {
   list = udp_rpc_server[entry];
   pos = max_index(list);
  }

  list[pos] = make_list(p, v);
  udp_rpc_server[entry] = list;
 }
}


portmap = get_kb_item("rpc/portmap");
if (!portmap) exit(0, "No portmapper");

soc = open_sock_tcp (portmap);
if (!soc) exit(0, "Connection refused on port "+portmap);
 

data = NULL;

# portmapper : prog:100000 version:2 procedure:DUMP(4)

packet = rpc_packet (prog:100000, vers:2, proc:0x04, data:data);
data = rpc_sendrecv (socket:soc, packet:packet);

if (isnull(data))
{
  close(soc);
  exit(1, "No answer to RPC DUMP");
}

register_stream(s:data);

tcp_rpc_server = udp_rpc_server = NULL;

repeat
{
 value = xdr_getdword();
 if (value)
 {
  program = xdr_getdword();
  version = xdr_getdword();
  protocol = xdr_getdword();
  port = xdr_getdword();

  if (stream_error())
    break;

  add_rpc_server (p:program, v:version, proto:protocol, port:port);
 }
}
until (!value || value == 0);


# first we list/register TCP services
foreach entry (keys(tcp_rpc_server))
{
 report = NULL;

 foreach svc (tcp_rpc_server[entry])
 {
  report += string(" - program: ", svc[0]);

  if (!isnull(rpc_info[string(svc[0])]))
  {
   name = rpc_info[string(svc[0])];
   report += string(" (",name,")");

   register_service(port:int(entry), proto:string("rpc-",name));
  }
  else
   register_service(port:int(entry), proto:string("rpc-",svc[0]));


  report += string(", version: ", svc[1], "\n");
 }

 report = string ("\n",
		"The following RPC services are available on TCP port ", entry, " :\n\n",
		report);

 security_note (port:int(entry), extra:report);
}

# then UDP services
foreach entry (keys(udp_rpc_server))
{
 report = NULL;

 foreach svc (udp_rpc_server[entry])
 {
  report += string(" - program: ", svc[0]);

  if (!isnull(rpc_info[string(svc[0])]))
  {
   name = rpc_info[string(svc[0])];
   report += string(" (",name,")");

   register_service(port:int(entry), proto:string("rpc-",name), ipproto:"udp");
  }
  else
   register_service(port:int(entry), proto:string("rpc-",svc[0]), ipproto:"udp");

  report += string(", version: ", svc[1], "\n");
 }

 report = string ("\n",
		"The following RPC services are available on UDP port ", entry, " :\n\n",
		report);

 security_note (port:int(entry), extra:report, proto:"udp");

}

