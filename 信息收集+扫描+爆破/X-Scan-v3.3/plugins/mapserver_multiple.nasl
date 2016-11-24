#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
 script_id(26010);
 script_version("$Revision: 1.7 $");

 script_cve_id("CVE-2007-4542", "CVE-2007-4629");
 script_bugtraq_id(25582);
 script_xref(name:"OSVDB", value:"39378");
 script_xref(name:"OSVDB", value:"39379");
 script_xref(name:"OSVDB", value:"41031");

 name["english"] = "MapServer Multiple Remote Vulnerabilities";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains CGI scripts that are prone to arbitrary
remote command execution and cross-site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running MapServer, an opensource internet map
server. 

The installed version of MapServer is affected by multiple cross-site
scripting vulnerabilities and to a buffer overflow vulnerability.  To
exploit those flaws an attacker needs to send specially-crafted
requests to the mapserv CGI. 

By exploiting the buffer overflow vulnerability, an attacker would be
able to execute code on the remote host with the privileges of the web
server." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MapServer 4.10.3." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 summary["english"] = "Checks for multiple vulnerabilities in MapServer < 4.10.3";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Try to find MapServer (Windows)
req = http_get(item:"/cgi-bin/mapserv.exe?map=nessus.map", port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if ("MapServer Message" >!< res) 
{
 # (Unix)
 req = http_get(item:"/cgi-bin/mapserv?map=nessus.map", port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
}

# Do a banner check.
if (
  'msLoadMap(): Unable to access file. (nessus.map)' >< res &&
  egrep(pattern:"<!-- MapServer version [0-9]+\.[0-9]+\.[0-9]+ ", string:res)
)
{
 version = ereg_replace(pattern:".*<!-- MapServer version ([0-9]+\.[0-9]+\.[0-9]+) .*", string:res, replace:"\1");
 vers = split(version, sep:".", keep:FALSE);

 if ( ( int(vers[0]) < 4 ) ||
	( int(vers[0]) == 4 && int(vers[1]) < 10 ) ||
	( int(vers[0]) == 4 && int(vers[1]) == 10 && int(vers[2]) < 3 ) )
 {
   security_hole(port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
 }
}
