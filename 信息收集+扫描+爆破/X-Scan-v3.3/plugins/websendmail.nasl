#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10301);
 script_version ("$Revision: 1.26 $");
 script_cve_id("CVE-1999-0196");
 script_bugtraq_id(2077);
 script_xref(name:"OSVDB", value:"237");
 
 script_name(english:"WebGais websendmail CGI Arbitrary Command Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that may suffer from an
arbitrary command execution flaw." );
 script_set_attribute(attribute:"description", value:
"The 'websendmail' program, part of Webgais, appears to be installed on
the remote host.  This CGI script has a well-known security flaw that
lets an attacker execute arbitrary commands with the privileges of the
http daemon (usually root or nobody)." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/1997_3/0018.html" );
 script_set_attribute(attribute:"solution", value:
"Remove the 'websendmail' program." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Checks for the presence of /cgi-bin/websendmail");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
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
res = is_cgi_installed3(item:"websendmail", port:port);
if(res)security_hole(port);

