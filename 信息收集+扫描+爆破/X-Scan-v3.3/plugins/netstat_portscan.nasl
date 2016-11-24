#TRUSTED 432dfbb46af615935db9ab1aa4be50c414cc695b8237f9e19daeb148683fd00548d8967e3d17ca66afc2a8b13f197ce7acdf7ae253a1bf02223c1d74b386b1200b72e879abe76bf48cef26dc86a7ef5050b80df62dd94414689384c14a032f189d1ed9aecd6a6dc444bf19ff398ed92e36f447c5066a609eaf1a842763494980589b886ed8759aaa7bcc6045187cd67b0fb54d4064307ddb85183e14e15b64435ae74088e5d8479213de6884ed147ef24625fb82f6c8541fa0c265593ca92b1cdb4e536b84555a60a762b3ee68d088b4340805b12f347ae9c5ff47db96838525c266242392db0affdb171fc025925de8d0003c55449b17c96bb10be5fdd7a060fcea76fab842622d90ad7e90718a89915dfbe0084570162b50628a2c44c1bcc5a86464c7c14295e697e5fa88ec010ec68ed773010cbb375cc3f0ef08401c0fad0b2e3b7450c5fde5c89963fef3959503f6069443d3931edf8b598220dadbd343288488601b790eddab93dda23b8490d27ca75487f4043839329f8150ce61345aea0a4bd738fa3791e71b6f637abe9447caa0dc87bbe490f616a6674d5b323f60cae3af7e8960d008c55c5c4c8a2d80b4f6bd7e29b41b5df29bc7d170841bc18e0f67265a3553b47d3fabf1b3a76a226b266c9dd0b2b911949f55d45a63be954eb828974c80c092ce16ad62b109c119cd165c0eb2b956524e704c4ee2dbe90277
#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
 script_id(14272);
 script_version("1.31");

 script_name(english: "netstat portscanner (SSH)");
 script_summary(english: "Find open ports with netstat");
 
 script_set_attribute(
  attribute:'synopsis',
  value:'Remote open ports are enumerated via SSH.'
 );
 script_set_attribute(
  attribute:'description',
  value:"This plugin runs 'netstat' on the remote machine to enumerate open
ports. 

See the section 'plugins options' to configure it."
 );
 script_set_attribute(
  attribute:"solution", 
  value:"n/a"
 );
 script_set_attribute(
  attribute:"risk_factor", 
  value:"None"
 );
 script_set_attribute(
  attribute:"plugin_publication_date", 
  value:"2004/08/15"
 );
 script_end_attributes();
 
 script_category(ACT_SCANNER);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english: "Port scanners");
 script_dependencies("ping_host.nasl", "ssh_settings.nasl", "portscanners_settings.nasl");
 exit(0);
}

#
include("ssh_func.inc");
include("ports.inc");

if ( get_kb_item("Host/full_scan") ) exit(0);

buf = "";

# On the local machine, just run the command
if (islocalhost())
{
  if ( ! defined_func("pread") ) exit(0);
  buf = pread(cmd: "netstat", argv: make_list("netstat", "-a", "-n"));
  set_kb_item(name:"Host/netstat", value:buf);
  set_kb_item(name:"Host/netstat/method", value:"local");
}
else
{
# First try the netstat service, just in case
 s = open_sock_tcp(15);
 if (s)
 {
   linenb = 0;
   while (r = recv(socket: s, length: 4096))
    {
     buf += r;
     linenb++;
     if ( linenb > 1024 ) break;
    }
   close(s);
 }
# Then try SSH if the result is not OK
 if ("LISTEN" >!< buf)
 {
 ret = ssh_open_connection();
 if (! ret )  exit(0);

 buf = ssh_cmd(cmd:"cmd /c netstat -an", timeout:60);

 if ("LISTENING" >!< buf && "0.0.0.0:0" >!< buf && "*.*" >!< buf)
 {
 buf = ssh_cmd(cmd:"netstat -a -n", timeout:60);
 if (! buf) { ssh_close_connection(); exit(1, "The 'netstat' command failed to be executed"); }
 }
 ssh_close_connection();
 set_kb_item(name:"Host/netstat", value:buf);
 set_kb_item(name:"Host/netstat/method", value:"ssh");
}
 else
 {
  set_kb_item(name:"Host/netstat", value:buf);
  set_kb_item(name:"Host/netstat/method", value:"port15");
 }
}

# display(buf);
ip = get_host_ip();
lines = split(buf);
n = max_index(lines);
if (n == 0) n = 1; i = 0;
scanner_status(current: 0, total: n);
scanned = 0;

check = get_kb_item("PortscannersSettings/probe_TCP_ports");
if (defined_func("get_preference") &&
    "yes" >< get_preference("unscanned_closed"))
 unscanned_closed = TRUE;
else
 unscanned_closed = FALSE;

if (unscanned_closed)
{
  tested_tcp_ports = get_tested_ports(proto: 'tcp');
  tested_udp_ports = get_tested_ports(proto: 'udp');
}
else
{
  tested_tcp_ports = make_list();
  tested_udp_ports = make_list();
}

foreach line (lines)
{
  # Windows
  v = eregmatch(pattern: '^[ \t]+(TCP|UDP)[ \t]+([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+):([0-9]+)[ \t]+(0\\.0\\.0\\.0:0|\\*\\.\\*)[ \t]+', string: line, icase: 0);
  # Unix
  if (isnull(v))
   v = eregmatch(pattern: '^(tcp|udp)[46]?[ \t]+.*[ \t]+(\\*|[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)[:.]([0-9]+)[ \t]+(.*[ \t]+LISTEN|0\\.0\\.0\\.0:\\*)', string: line, icase: 1);

  if (isnull(v))
  # tcp 0 0 :::22   :::*    LISTEN
  # tcp 0 0 ::1:25  :::*    LISTEN (1 = localhost)
  # tcp6 0 0 :::22 :::* LISTEN 
  v = eregmatch(pattern: '^(tcp|udp)[46]?[ \t]+.*[ \t]+(:::)([0-9]+)[ \t]+.*[ \t]+LISTEN', string: line, icase: 1);


  # Solaris 9
  if (isnull(v))
  {
    if (last_seen_proto)
    {
      if (last_seen_proto == 'udp')
        v = eregmatch(pattern: '^[ \t]*(\\*|[0-9.]+)\\.([0-9]+)[ \t]+Idle', string: line);
      else
        v = eregmatch(pattern: '^[ \t]*(\\*|[0-9.]+)\\.([0-9]+)[ \t]+\\*\\.\\*[ \t]+.*(Idle|LISTEN)', string: line);
      
      if (! isnull(v))
      {
        # "Fix" array
        v[3] = v[2]; v[2] = v[1]; v[1] = last_seen_proto;
      }
    }
    if (isnull(v))
    {
      v = eregmatch(pattern: '^(TCP|UDP): +IPv4[ \t\r\n]*$', string: line);
      if (!isnull(v))
      {
        last_seen_proto = tolower(v[1]);
        v = NULL;
      }
    }
  }
  

  if (!isnull(v))
  {
    proto = tolower(v[1]);
    addr = v[2];
    port = int(v[3]);
    checktcp = (check && proto == "tcp");
    # display("> ", addr, ":", port, " (", proto, ")\n");
    if (port < 1 || port > 65535)
     display('netstat_portscan(', get_host_ip(), '): invalid port number ', port, '\n');
    else if (checktcp || addr == "0.0.0.0" || addr == ip || addr == ":::" || addr == '*')
    {
      if (unscanned_closed)
        if (proto == "tcp" && ! tested_tcp_ports[port] ||
	    proto == "udp" && ! tested_udp_ports[port] )
	  continue;

      if (checktcp)
      {
        soc = open_sock_tcp(port);
        if (soc)
        {
          scanner_add_port(proto: proto, port: port);
          close(soc);
        }
      }
      else
      scanner_add_port(proto: proto, port: port);
      # display(proto, "\t", port, "\n");
    }
    scanned ++;
  }
  scanner_status(current: i++, total: n);
}

if (scanned)
{
 set_kb_item(name: "Host/scanned", value: TRUE);
 set_kb_item(name: "Host/udp_scanned", value: TRUE);
 set_kb_item(name: "Host/full_scan", value: TRUE);

 set_kb_item(name: "Host/TCP/scanned", value: TRUE);
 set_kb_item(name: "Host/UDP/scanned", value: TRUE);
 set_kb_item(name: "Host/TCP/full_scan", value: TRUE);
 set_kb_item(name: "Host/UDP/full_scan", value: TRUE);

 set_kb_item(name: 'Host/scanners/netstat', value: TRUE);
}

scanner_status(current: n, total: n);
exit(0);
