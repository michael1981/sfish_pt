#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10535);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-2000-0967");
 script_bugtraq_id(1786);
 script_xref(name:"OSVDB", value:"434");

 script_name(english:"PHP Error Log Format String Command Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code might be run on the remote host." );
 script_set_attribute(attribute:"description", value:
"A version of PHP which is older than 3.0.17 or than 4.0.3 is running on 
this host.

If the option 'log_errors' is set to 'On' in php.ini, then an attacker 
may execute arbitrary code on this host." );
 script_set_attribute(attribute:"solution", value:
"Make sure that 'log_errors' is set to 'Off' in your php.ini, or install 
the latest version of PHP." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Checks for version of PHP");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

 banner = get_http_banner(port:port);
 if(!banner)exit(0);

 serv = egrep(string:banner, pattern:"^Server:.*$");
 if(ereg(pattern:"(.*PHP/3\.0\.((1[0-6])|([0-9]([^0-9]|$))))|(.*PHP/4\.0\.[0-2]([^0-9]|$))",
          string:serv))
 {
   security_warning(port);
 }
 
