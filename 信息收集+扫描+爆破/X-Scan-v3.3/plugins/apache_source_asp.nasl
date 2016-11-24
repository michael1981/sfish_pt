#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10480);
 script_bugtraq_id(1457);
 script_version ("$Revision: 1.22 $");
 script_cve_id("CVE-2000-0628");
 script_xref(name:"OSVDB", value:"379");
 script_name(english:"Apache ASP module Apache::ASP source.asp Example File Arbitrary File Creation");
 script_summary(english:"Checks for the presence of /site/eg/source.asp");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an arbitrary file creation
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The file /site/eg/source.asp is present on the remote Apache web
server.

This file comes with the Apache::ASP package and allows anyone to
write to files in the same directory. An attacker may use this flaw
to upload his own scripts and execute arbitrary commands on this host." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2000-07/0142.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Apache::ASP 1.95 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/apache", "Settings/ParanoidReport");
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

sig = get_kb_item("www/hmap/"  + port  + "/description");
if ( sig && "Apache" >!< sig ) exit(0);


res = is_cgi_installed3(port:port, item:"/site/eg/source.asp");
if( res )
{
 security_hole(port);
}
