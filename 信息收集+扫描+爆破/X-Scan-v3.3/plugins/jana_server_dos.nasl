#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(15862);
 script_version("$Revision: 1.4 $");
 script_bugtraq_id(11780);
 script_xref(name:"OSVDB", value:"12172");
 script_xref(name:"OSVDB", value:"12173");
 script_xref(name:"Secunia", value:"13333");

 script_name(english:"JanaServer < 2.4.5 Multiple Remote DoS");
 script_summary(english:"Checks for version of JanaServer");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote service has multiple denial of service vulnerabilities."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "According to its banner, the version of JanaServer running on the\n",
     "remote host has the following denial of service vulnerabilities :\n\n",
     "  - The 'http-server' module (TCP port 2506) does not\n",
     "    correctly process requests containing a lot of\n",
     "    occurences of the '%' character, causing it to\n",
     "    consume a large amount of CPU resources.\n\n",
     "  - The 'pna-proxy' module (TCP port 1090) has an infinite\n",
     "    loop vulnerability when it receives a data block size\n",
     "    larger than the amount of data that is actually sent.\n\n",
     "A remote attacker can reportedly freeze the server after fifteen or\n",
     "more attempts to exploit these vulnerabilities."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2004-11/0395.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to JanaServer 2.4.5 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");

 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");

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

port = get_http_port(default:80);
banner = get_http_banner(port: port);
if(!banner)exit(0);
 
if ( egrep(pattern:"^Server: Jana-Server/([01]\.|2\.([0-3]\.|4\.[0-4][^0-9]))", string:banner) )
	security_hole(port);
