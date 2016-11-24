#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10359);
 script_version ("$Revision: 1.22 $");

 script_xref(name:"OSVDB", value:"274");

 script_name(english:"Microsoft IIS ctss.idc ODBC Sample Arbitrary Command Execution");
 script_summary(english:"Checks for the presence of /scripts/tools/ctss.idc");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "A web application on the remote host has an arbitrary command\n",
     "execution vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "/scripts/tools/ctss.idc is present.  Input to the 'table' parameter\n",
     "is not properly sanitized.  A remote attacker could exploit this to\n",
     "execute arbitrary SQL commands.  If xp_cmdshell is enabled, this\n",
     "could result in arbitrary command execution."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/sf/pentest/2001-07/0189.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Remove this application from the server."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);

cgi = "/scripts/tools/ctss.idc";
res = is_cgi_installed3(item:cgi, port:port);
if(res)security_hole(port);

