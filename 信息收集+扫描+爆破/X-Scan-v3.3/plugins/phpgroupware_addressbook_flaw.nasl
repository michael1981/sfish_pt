#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
# This script is released under the GNU GPLv2
#


include("compat.inc");

if(description)
{
 script_id(19753);
 script_version ("$Revision: 1.3 $");
 script_bugtraq_id(14141);
 script_xref(name:"OSVDB", value:"7669");

 script_name(english:"phpGroupWare < 0.9.16 Addressbook Unspecified Vulnerability");

 script_set_attribute(attribute:"synopsis", value:
"A remote web application is vulnerable to an unspecified flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running PhpGroupWare, is a multi-user
groupware suite written in PHP. 

This version is prone to an unspecified flaw related to its addressbook." );
 script_set_attribute(attribute:"solution", value:
"Update to version 0.9.16.000 or newer." );
 script_set_attribute(attribute:"see_also", value:"http://www.phpgroupware.org/" );
 script_set_attribute(attribute:"risk_factor", value:"Low" );

script_end_attributes();

 
 script_summary(english:"Checks for PhpGroupWare version");
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 David Maciejak");
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
if ( ereg(pattern:"^0\.([0-8]\.|9\.([0-9]\.|1[0-5]\.$))", string:matches[1]))
	security_note(port);
