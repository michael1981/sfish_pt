#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
# This script is released under the GNU GPLv2

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref (3/31/2009)


include("compat.inc");

if(description)
{
 script_id(14294);
 script_version ("$Revision: 1.9 $");
 script_bugtraq_id(8265);
 script_xref(name:"OSVDB", value:"53008");

 script_name(english:"phpGroupWare Unspecified Remote File Inclusion");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote host" );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running PhpGroupWare, is a multi-user 
groupware suite written in PHP.

This version is prone to a vulnerability that may permit remote 
attackers, without prior authentication, to include and execute 
malicious PHP scripts. 
Remote users may influence URI variables to include a malicious PHP 
script on a remote system, it is possible to cause arbitrary PHP code to
be executed." );
 script_set_attribute(attribute:"solution", value:
"Update to version 0.9.14.006 or newer" );
 script_set_attribute(attribute:"see_also", value:"http://www.phpgroupware.org/" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_summary(english:"Checks for PhpGroupWare version");
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"CGI abuses");
 script_dependencie("phpgroupware_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

kb = get_kb_item("www/" + port + "/phpGroupWare");
if (! kb ) exit(0);

matches = eregmatch(pattern:"(.*) under (.*)", string:kb);
if ( ereg(pattern:"^0\.([0-8]\.|9\.([0-9]\.|1[0-3]\.|14\.0*[0-5]([^0-9]|$)))", string:matches[1]) )
	security_hole(port);
