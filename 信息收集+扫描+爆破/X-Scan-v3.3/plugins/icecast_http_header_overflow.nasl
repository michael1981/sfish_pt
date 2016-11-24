#
# (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
 script_id(14843);
 script_version ("$Revision: 1.13 $");

 script_cve_id("CVE-2004-1561");
 script_bugtraq_id(11271);
 script_xref(name:"OSVDB", value:"10446");
 script_xref(name:"Secunia", value:"12666");
 
 script_name(english:"Icecast HTTP Header Processing Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote web server runs Icecast version 2.0.1 or older.  Such
versions are affected by an HTTP header buffer overflow vulnerability
that may allow an attacker to execute arbitrary code on the remote
host with the privileges of the Icecast server process. 

To exploit this flaw, an attacker needs to send 32 HTTP headers to the
remote host to overwrite a return address on the stack." );
 script_set_attribute(attribute:"see_also", value:"http://aluigi.altervista.org/adv/iceexec-adv.txt" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2004-09/0366.html" );
 script_set_attribute(attribute:"see_also", value:"http://lists.xiph.org/pipermail/icecast/2004-September/007614.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Icecast 2.0.2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
 summary["english"] = "Checks Icecast version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_MIXED_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
		
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8000);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("http_func.inc");

port = get_http_port(default:8000);
if(!port) exit(0);

banner = get_http_banner(port:port);
if (report_paranoia < 2)
{
  if (!banner || "server: icecast/" >!< tolower(banner)) exit(0);
}

if ( safe_checks() )
{
  if ( ! banner ) exit(0);
  if(egrep(pattern:"^Server: icecast/2\.0\.[0-1][^0-9]", string:banner, icase:TRUE))
      security_hole(port);
}
else
{
  soc = open_sock_tcp(port);
  if ( ! soc ) exit(0);

  req = string("GET / HTTP/1.1\r\nHost: localhost\r\n");
  for ( i = 0 ; i < 31 ; i ++ ) req += string("Header", i, ": fooBar\r\n");
  req += string("\r\n");
  send(socket:soc, data:req);
  r = recv(socket:soc, length:4096);
  if ( r ) exit(0);
  close(soc);

  if (http_is_dead(port:port)) security_hole(port);
}
