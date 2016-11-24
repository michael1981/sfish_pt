#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(16475);
 script_version("$Revision: 1.5 $");
 script_cve_id("CVE-2005-0453");
 script_bugtraq_id(12567);
 script_xref(name:"OSVDB", value:"13844");
 
 script_name(english:"lighttpd Null Byte Request CGI Script Source Code Disclosure");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running lighttpd, a small webserver.

This version of lighttpd is vulnerable to a flaw wherein an attacker,
by requesting a CGI script appended by a '%00', will be able to read
the source of the script." );
 script_set_attribute(attribute:"see_also", value:"http://article.gmane.org/gmane.comp.web.lighttpd/1171" );
 script_set_attribute(attribute:"see_also", value:"http://www.gentoo.org/security/en/glsa/glsa-200502-21.xml" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to lighttpd 1.3.8 or later" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english:"Checks for version of Sami HTTP server");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http.inc");
include("misc_func.inc");
include("global_settings.inc");

port = get_http_port(default:80);

if(!get_port_state(port)) exit (0);

banner = get_http_banner(port: port);
if(!banner)exit(0);

if ( egrep(pattern:"^Server: lighttpd/(0\.|1\.([0-2]\.|3\.[0-7][^0-9]))", string:banner) ) 
 {
   security_warning(port);
 }

