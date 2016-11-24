#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) 
{
  script_id(25082);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2007-1681");
  script_bugtraq_id(23539);
  script_xref(name:"OSVDB", value:"34902");

  script_name(english:"Sun Java Web Console LibWebconsole_Services.SO Remote Format String");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to a format string attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running SUN Java Web Console. 

The remote version of this service does not properly sanitize calls
to the syslog function. By sending a specially crafted request
it is possible to exploit this format string error.
An attacker can exploit it to execute code with the privileges of
the web server." );
 script_set_attribute(attribute:"solution", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-26-102854-1" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_end_attributes();

  script_summary(english:"Checks Sun Java Web Console Version");
  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
  script_dependencie("http_version.nasl", "ssh_detect.nasl");
  script_require_ports("Services/www", 6789);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");


function https_send_recv (port, data)
{
 local_var soc, buf;

 soc = open_sock_tcp(port, transport:ENCAPS_SSLv23);
 if (!soc)
   exit (0);

 send(socket:soc, data:data);
 buf = http_recv_body(socket:soc, length:0);
 if (!buf)
   exit (0);

 return buf;
}


ssh_port = get_kb_item("Services/ssh");
if (!ssh_port)
  exit(0);

banner = get_kb_item(string("SSH/banner/", ssh_port));
if ("Sun_SSH" >!< banner)
  exit(0); 

port = 6789;
if (!get_port_state(port))
  exit(0);


req = http_get(item:"/console/html/en/console_version.shtml", port:port);
res = https_send_recv(port:port, data:req);
if (res == NULL)
  exit(0);

if ("<title>Sun Java(TM) Web Console: Version</title>" >!< res)
  exit (0);

req = http_get(item:"/console/html/en/version.txt", port:port);
res = https_send_recv(port:port, data:req);
if (res == NULL)
  exit(0);

if (!egrep(pattern:"^[0-9]+\.[0-9]+\.[0-9]+$", string:res))
  exit (0);

vers = ereg_replace(pattern:"^([0-9]+\.[0-9]+\.[0-9]+)$", string:res, replace:"\1");
vers = split(vers, sep:".", keep:FALSE);

if ( (int(vers[0]) < 2) ||
     ((int(vers[0]) == 2) && (int(vers[1]) < 2)) ||
     ((int(vers[0]) == 2) && (int(vers[1]) == 2) && (int(vers[2]) < 6)) )
{
 # patched in 2.2.6 except for solaris 10 ( patched in 2.2.4 )
 req = http_get(item:"/console/html/en/versionDate.txt", port:port);
 res = https_send_recv(port:port, data:req);
 if (res == NULL)
   exit(0);

 if (!egrep(pattern:"^[0-9]+/[0-9]+/[0-9]+$", string:res))
   exit (0);
 
 date = ereg_replace(pattern:"$([0-9]+/[0-9]+/[0-9]+)$", string:res, replace:"\1");
 date = split(vers, sep:"/", keep:FALSE);

 if ( int(date[0]) < 2007 ||
      (int(date[0]) == 2007 && int(date[1]) < 3) )
   security_hole(port);
}
