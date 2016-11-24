#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10340);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-2000-0192");
 script_bugtraq_id(1036);
 script_xref(name:"OSVDB", value:"258");
 
 script_name(english:"rpm_query CGI System Information Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The rpm_query CGI is installed. 

This CGI allows anyone who can connect to this web server to obtain the
list of the installed RPMs.

This allows an attacker to determine the version number of your 
installed services, hence making their attacks more accurate." );
 script_set_attribute(attribute:"solution", value:
"Remove this CGI from cgi-bin/" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english:"checks for rpm_query");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "webmirror.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

#
# The script code starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);
res = is_cgi_installed3(item:"rpm_query", port:port);
if(res) security_warning(port);
