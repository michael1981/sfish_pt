#
# (C) Tenable Network Security, Inc.
#

# References:
# From: <gregory.lebras@security-corporation.com>
# To: vulnwatch@vulnwatch.org
# Date: Thu, 27 Mar 2003 15:25:40 +0100
# Subject: [SCSA-012] Multiple vulnerabilities in Sambar Server
#
# Vulnerables:
# Sambar WebServer v5.3 and below 
#

include("compat.inc");


if(description)
{
 script_id(11775);
 script_version ("$Revision: 1.8 $");

 script_cve_id("CVE-2003-1284");
 script_bugtraq_id(7207, 7208);
 script_xref(name:"OSVDB", value:"5094");
 script_xref(name:"OSVDB", value:"5093");

 script_name(english:"Sambar Server Multiple CGI Environment Variable Disclosure");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The remote web server contains CGI scripts that are affected by information\n",
     "disclosure vulnerabilities."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote web server appears to be Sambar Server and makes available\n",
     "the 'environ.pl' and/or 'testcgi.exe' CGI scripts.  These are included\n",
     "by default and reveal the server's installation directory along with\n",
     "other information that could prove useful to an attacker.\n",
     "\n",
     "Note that this version is also likely to be affected by other issues,\n",
     "including arbitrary code execution, although this plugin has not\n",
     "checked for them."
   )
 );
 script_set_attribute(
   attribute:"see_also", 
   value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=103"
 );
 script_set_attribute(
   attribute:"see_also", 
   value:"http://archives.neohapsis.com/archives/bugtraq/2003-03/0420.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Delete the affected CGI scripts."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
 );
 script_end_attributes();

 script_summary(english:"Some CGIs reveal the web server installation directory");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/sambar");
 exit(0);
}

# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if (!banner) exit(0);
if (!egrep(pattern:"^Server:.*SAMBAR.*", string:banner)) exit(0);

req = http_get(item:"/cgi-bin/testcgi.exe", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if( res == NULL ) exit(0);

if("SCRIPT_FILENAME" >< res ) {
        security_warning(port);
        exit(0);
        }
        
        
req = http_get(item:"/cgi-bin/environ.pl", port:port);  
res = http_keepalive_send_recv(port:port, data:req);
if( res == NULL ) exit(0);

if("DOCUMENT_ROOT" >< res) security_warning(port);
