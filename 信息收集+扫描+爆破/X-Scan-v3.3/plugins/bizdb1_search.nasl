#
# Locate /cgi-bin/bizdb1-search.cgi
#
# This plugin was written in NASL by RWT roelof@sensepost.com 26/4/2000
# Regards,
# Roelof@sensepost.com


include("compat.inc");

if(description)
{
 script_id(10383);
 script_bugtraq_id(1104);
 script_version ("$Revision: 1.22 $");
 script_cve_id("CVE-2000-0287");
 script_xref(name:"OSVDB", value:"291");

 script_name(english:"BizDB bizdb-search.cgi Arbitrary Command Execution");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application with a remote command
execution vulnerability." );
 script_set_attribute(attribute:"description", value:
"BizDB is a web database integration product using Perl CGI scripts.
One of the scripts, bizdb-search.cgi, passes a variable's contents
to an unchecked open() call and can therefore be made to execute
commands at the privilege level of the webserver.

The variable is dbname, and if passed a semicolon followed by shell
commands they will be executed. This cannot be exploited from a
browser, as the software checks for a referrer field in the HTTP
request. A valid referrer field can however be created and sent
programmatically or via a network utility like netcat." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2000-04/0058.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of the software." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );


script_end_attributes();

 summary["english"] = "Determines the presence of cgi-bin/bizdb1-search.cgi";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2009 Roelof Temmingh <roelof@sensepost.com>");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);

cgi = string("bizdb1-search.cgi");
res = is_cgi_installed_ka(item:cgi, port:port);
if( res ) {
	if ( is_cgi_installed_ka(item:"nessus" + rand() + ".cgi", port:port) ) exit(0);
	security_hole(port);
}
