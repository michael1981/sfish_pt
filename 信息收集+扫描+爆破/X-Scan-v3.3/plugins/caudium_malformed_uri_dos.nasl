#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(15625);
 script_bugtraq_id(11567);
 script_xref(name:"OSVDB", value:"11255");
 script_xref(name:"Secunia", value:"13040");

 script_version("$Revision: 1.6 $");
 script_name(english:"Caudium Web Server Malformed URI Remote DoS");
 script_summary(english:"Checks for version of Caudium");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote web server has a denial of service vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host is running the Caudium Web Server.\n\n",
     "The remote version of this software is vulnerable to an attack wherein\n",
     "a malformed URI causes the webserver to stop responding to requests.\n\n",
     "A remote attacker could disable this service by issuing a specially\n",
     "crafted HTTP GET request."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/fulldisclosure/2004-12/0490.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://sourceforge.net/tracker/index.php?func=detail&aid=1028622&group_id=8825&atid=108825"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Caudium 1.4.4 RC2 or newer."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P"
 );
 script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 443);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

banner = get_http_banner(port: port);
if(!banner)exit(0);
 
serv = strstr(banner, "Server");
if(ereg(pattern:"^Server: Caudium/(0\..*|1\.[0-3]\..*|1\.4\.[0-3])", string:serv) )
 {
   security_warning(port);
 }
