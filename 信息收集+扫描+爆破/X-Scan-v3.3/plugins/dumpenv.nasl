#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10060);
 script_version ("$Revision: 1.26 $");
 script_cve_id("CVE-1999-1178");
 script_xref(name:"OSVDB", value:"52");

 script_name(english:"Sambar Server dumpenv.pl Information Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has a CGI script that is affected by information
disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"CGI script 'dumpenv.pl' is installed on the remote host. This CGI 
gives away too much information about the web server configuration, 
which will help an attacker." );
 script_set_attribute(attribute:"solution", value:
"Remove it from /cgi-bin." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english:"Checks for the presence of /cgi-bin/dumpenv");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
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

cgi = "dumpenv.pl";
res = is_cgi_installed3(item:cgi, port:port);
if( res )security_warning(port);
