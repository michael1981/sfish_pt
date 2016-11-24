#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11338);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-2003-0123", "CVE-2001-1311");
 script_bugtraq_id(3041, 7038, 7039);
 script_xref(name:"OSVDB", value:"10815");
 script_xref(name:"OSVDB", value:"10829");

 script_name(english:"IBM Lotus Domino < 5.0.12 / 6.0.1 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitray code may be run on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote Lotus Domino server, according to its version number,
is vulnerable to various buffer overflows affecting it when
it acts as a client (through webretriever) or in LDAP.

An attacker may use these to disable this server or
execute arbitrary commands on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www.rapid7.com/advisories/R7-0011.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.rapid7.com/advisories/R7-0012.html" );
 script_set_attribute(attribute:"solution", value:
"Update to Domino 5.0.12 or 6.0.1" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_summary(english:"Checks for the version of the remote Domino Server");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 script_dependencie("http_version.nasl", "webmirror.nasl", "www_fingerprinting_hmap.nasl");
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

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "Lotus Domino" >!< sig ) exit(0);

banner = get_http_banner(port:port);
if(!banner)exit(0);


if(egrep(pattern:"^Server: Lotus-Domino/(Release-)?(4\..*|5\.0.?([0-9]|1[0-1])[^0-9])", string:banner))security_hole(port);
