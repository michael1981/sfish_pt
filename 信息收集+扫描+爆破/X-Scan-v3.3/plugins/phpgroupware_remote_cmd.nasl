#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
# Ref: Secure Reality Pty Ltd. Security Advisory #6 on December 6, 2000.
#
# This script is released under the GNU GPLv2
#

# Changes by Tenable:
# - Revised plugin title (3/31/2009)

include("compat.inc");

if(description)
{
 script_id(15711);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2001-0043");
 script_bugtraq_id(2069);
 script_xref(name:"OSVDB", value:"1682");
	
 script_name(english:"phpGroupWare phpgw.inc.php phpgw_info Parameter Remote File Inclusion");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary commands may be run on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running PhpGroupWare, is a multi-user groupware 
suite written in PHP.

This version is prone to a vulnerability that may permit remote attackers
to execute arbitrary commands by triggering phpgw_info parameter of the 
phpgw.inc.php script, resulting in a loss of integrity." );
 script_set_attribute(attribute:"solution", value:
"Update to version 0.9.7 of this software or newer" );
 script_set_attribute(attribute:"see_also", value:"http://www.phpgroupware.org/" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 summary["english"] = "Checks for PhpGroupWare version";
 
 script_summary(english:summary["english"]);
 
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

port = get_http_port(default:80);

kb = get_kb_item("www/" + port + "/phpGroupWare");
if ( ! kb ) exit(0);

matches = eregmatch(pattern:"(.*) under (.*)", string:kb);

if ( ereg(pattern:"^0\.([0-8]\.|9\.[0-6][^0-9])", string:matches[1]) ) 
	security_hole(port);
