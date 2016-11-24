#
# This script written by Scott Shebby (12/2003) 
#

# See the Nessus Scripts License for details
#
# Ref:
# From: "Ruso, Anthony" <aruso@positron.qc.ca>
# To: Penetration Testers <PEN-TEST@SECURITYFOCUS.COM>
# Subject: Sgdynamo.exe Script -- Path Disclosure
# Date: Wed, 16 May 2001 11:55:32 -0400
#
# Changes by Tenable:
#	- Description  [RD]
#	- Support for multiple CGI directories  [RD]
#	- HTTP KeepAlive support  [RD]
#	- egrep() instead of eregmatch()  [RD]
#       - updated title (4/29/09)
#       - Updated to use compat.inc, added CVSS score (11/20/2009)


include("compat.inc");

if(description)
{
 script_id(11954);
 script_version ("$Revision: 1.10 $");
 script_xref(name:"OSVDB", value:"54010");

 script_name(english:"SGDynamo sgdynamo.exe HTNAME Parameter Path Disclosure");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by an 
information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The CGI 'sgdynamo.exe' can be tricked into giving the 
physical path to the remote web root.

This information may be useful to an attacker who can use 
it to make better attacks against the remote server." );
 script_set_attribute(attribute:"solution", value:
"None at this time" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english:"sgdynamo.exe Path Disclosure");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Scott Shebby");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
 url = dir + "/sgdynamo.exe?HTNAME=sgdynamo.exe";
 req = http_get(item:url, port:port);
 resp = http_keepalive_send_recv(port:port, data:req);
 if ( resp == NULL ) exit(0);
 path = egrep(pattern:"[aA-zZ]:\\.*sgdynamo\.exe", string:resp);
 if (path) {
   path = ereg_replace(string:path, pattern:".*([aA-zZ]:\\.*sgdynamo\.exe).*", replace:"\1");
   report = 
"
It is possible to obtain the phyiscal path to the remote website by sending
the following request :

" + egrep(pattern:"^GET /", string:req) + "

We determined that the remote web path is : '" + path + "'
This information may be useful to an attacker who can use it to make better
attacks against the remote server.";

   security_warning(port:port, extra:report);
   exit(0);
  }
}
