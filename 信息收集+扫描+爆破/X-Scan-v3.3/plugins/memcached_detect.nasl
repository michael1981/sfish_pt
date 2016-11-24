#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(26197);
 script_version ("$Revision: 1.5 $");
 
 script_name(english: "memcached Detection");
 
 script_set_attribute(
  attribute:"synopsis",
  value:"Memcached is running on this port."
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "Memcached, a memory-based object store, is listening on the remote\n",
   "port."
  )
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://www.danga.com/memcached/"
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://www.eu.socialtext.net/memcached/index.cgi"
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://meta.wikimedia.org/wiki/Memcached"
 );
 script_set_attribute(
  attribute:"solution", 
  value:string(
   "As it is biased towards performance, memcached does not provide any\n",
   "kind of security by itself.  Make sure that the machine is properly\n",
   "protected by a firewall and that traffic to the port is restricted to\n",
   "authorized hosts."
  )
 );
 script_set_attribute(
  attribute:"risk_factor", 
  value:"None"
 );
 script_end_attributes();
 
 script_summary(english: 'Sends stats command to memcached');
 
 script_category(ACT_GATHER_INFO); 
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 script_family(english: "Service detection");
 script_dependencie("find_service2.nasl");
 script_require_ports(11211, "memcached/possible_port");
 exit(0);
}


include("global_settings.inc");
include("misc_func.inc");

function test(port)
{
 local_var	info, r, report, s, v, ver;

 if (! get_port_state(port)) return;
 s = open_sock_tcp(port);
 if (! s) return;

 # See <http://cvs.danga.com/browse.cgi/wcmtools/memcached/doc/protocol.txt>.
 send(socket: s, data: 'stats\r\n');
 r = recv(socket: s, length: 1024, min:5);
 v = eregmatch(string: r, pattern: '^STAT (pid|time|uptime|version) [0-9.]+\r\n');
 if (! isnull(v))
 {
  register_service(port:port, proto:'memcached');

  ver = "";
  if ("STAT version " >< r)
  {
    ver = strstr(r, "STAT version ") - "STAT version ";
    ver = ver - strstr(ver, '\r\n');
    if (ver && ver =~ '^[0-9]+[0-9.]+$') 
      set_kb_item(name: 'memcache/version/'+port, value: ver);
  }

  info = str_replace(find:"STAT ", replace:"  ", string:r);
  info = info - strstr(info, "END");
  report = string(
    "\n",
    "Nessus was able to gather the following statistics from the remote\n",
    "memcached server :\n",
    "\n",
    info
  );
  security_note(port:port, extra:report);
 }
 close(s);
}


test(port: 11211);

ports_l = get_kb_list("memcached/possible_port");
if ( isnull(ports_l) ) exit(0);
foreach port (make_list(ports_l)) if ( port != 11211 ) test(port: port);
