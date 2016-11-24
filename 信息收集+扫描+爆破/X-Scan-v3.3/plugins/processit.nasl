#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10649);
 script_version ("$Revision: 1.11 $");
 script_xref(name:"OSVDB", value:"538");

 script_name(english:"processit CGI Environment Variable Remote Information Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web is affected by an information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The 'processit' CGI is installed. processit normally returns all 
environment variables.

This gives an attacker valuable information about the configuration 
of your web server." );
 script_set_attribute(attribute:"solution", value:
"Remove it from /cgi-bin." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english:"Checks for the presence of /cgi-bin/processit");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "webmirror.nasl");
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

cgi = "processit.pl";
res = is_cgi_installed3(port:port, item:cgi);
if(res)security_warning(port);

