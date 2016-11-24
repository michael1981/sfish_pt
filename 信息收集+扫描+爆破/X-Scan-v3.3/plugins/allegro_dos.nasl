#
# Sarju Bhagat <sarju@westpoint.ltd.uk>
#
# GPLv2


include("compat.inc");

if(description)
{
 script_id(19304);
 script_bugtraq_id(1290);
 script_cve_id("CVE-2000-0470");
 script_xref(name:"OSVDB", value:"1371");
 script_version("$Revision: 1.5 $");
 script_name(english:"Allegro Software RomPager 2.10 Malformed Authentication Request DoS");

 script_set_attribute(attribute:"synopsis", value:
"The remote system is prone to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Allegro Software RomPager version 2.10,
according to its banner.  This version is vulnerable to a denial of
service attack that can be exploited by sending a specifically-crafted
request to crash the affected system." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2000-05/0398.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to v2.20 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C" );
script_end_attributes();


 summary["english"] = "Checks for version of Allegro Software RomPager";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005-2009 Westpoint Limited");
 script_family(english:"Denial of Service");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
 banner = get_http_banner(port:port);
 if(!banner || "Allegro" >!< banner )exit(0);

 serv = strstr(banner, "Server");
 if(ereg(pattern:"Allegro-Software-RomPager/2\.([0-9][^0-9]|10)", string:serv))
 {
   security_hole(port);
   exit(0);
 }
}
