#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10304);
 script_version ("$Revision: 1.22 $");
 script_cve_id("CVE-2000-0127");
 script_bugtraq_id(969);
 script_xref(name:"OSVDB", value:"240");
 
 script_name(english:"WebSpeed Messenger Administration Utility Unauthenticed Access");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is prone to privilege
escalation attacks." );
 script_set_attribute(attribute:"description", value:
"The remote web server appears to be using Webspeed, a website creation
language used with database-driven websites. 

The version of Webspeed installed on the remote host allows anonymous
access to the 'WSMadmin' utility, which is used configure Webspeed.  An
attacker can exploit this issue to gain control of the affected
application." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2000-02/0013.html" );
 script_set_attribute(attribute:"solution", value:
"Edit the 'ubroker.properties' file and change 'AllowMsngrCmds=1' to
'AllowMsngrCmds=0'." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_summary(english:"Checks if webspeed can be administered");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("Settings/ParanoidReport");
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

cgi = "/scripts/wsisa.dll/WService=anything?WSMadmin";
res = is_cgi_installed3(item:cgi, port:port);
if(res)security_hole(port);
 


