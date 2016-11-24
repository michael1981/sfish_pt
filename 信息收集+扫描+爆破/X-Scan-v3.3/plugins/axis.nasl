#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10023);
 script_bugtraq_id(1025);
 script_version ("$Revision: 1.25 $");
 script_cve_id("CVE-2000-0191");
 script_xref(name:"OSVDB", value:"19");

 script_name(english:"Axis Storpoint CD Admin Authentication Bypass");
 script_summary(english:"Requests /cd/../config/html/cnf_gi.htm");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an authentication bypass vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Axis StorPoint. It is possible to access
the administration interface with a specially crafted URL that
contains directory traversal characters." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2000-02/0395.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Axis StorPoint 4.28 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
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

cgi_should_fail = "/config/html/cnf_gi.htm";
cgi_should_succeed = "/cd/../config/html/cnf_gi.htm";

port = get_http_port(default:80);

res = is_cgi_installed3(port:port, item:cgi_should_fail);
if ( ! res )
{
 res = is_cgi_installed3(port:port, item:cgi_should_succeed);
 if ( res ) security_hole(port);
}
