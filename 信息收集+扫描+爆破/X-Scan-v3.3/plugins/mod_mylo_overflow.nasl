#
# (C) Tenable Network Security, Inc.
#

# The overflow occurs *after* the server replied to us, so it can only
# be detected using the banner of the server
#

include("compat.inc");

if(description)
{
 script_id(11809);
 script_version("$Revision: 1.12 $");
 script_cve_id("CVE-2003-0651");
 script_bugtraq_id(8287);
 script_xref(name:"OSVDB", value:"10976");
 script_xref(name:"Secunia", value:"9375");
 script_xref(name:"milw0rm", value:"67");
 
 script_name(english:"mod_mylo for Apache mylo_log Logging Function HTTP GET Overflow");
 script_summary(english:"Checks for version of mod_mylo");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote web server module has a buffer overflow vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "According to the banner, the remote host is using a vulnerable\n",
     "version of mylo_log, a MySQL logging module for Apache.  Such\n",
     "versions have a buffer overflow vulnerability which could result\n",
     "in arbitrary code execution."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2003-07/0355.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to mod_mylo 0.2.2 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");

 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
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

serv = strstr(banner, "Server:");
if(ereg(pattern:".*Mylo/(0\.[0-2]).*", string:serv))
{
  security_hole(port);
}
