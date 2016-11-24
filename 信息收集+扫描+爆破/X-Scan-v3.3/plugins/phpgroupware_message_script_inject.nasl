#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
# This script is released under the GNU GPLv2
#

# Changes by Tenable:
# - Added CVE / OSVDB (3/31/2009)


include("compat.inc");

if(description)
{
 script_id(19754);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2005-2761");
 script_bugtraq_id(14724);
 script_xref(name:"OSVDB", value:"18979");

 script_name(english:"phpGroupWare Main Screen Message Body XSS");

 script_set_attribute(attribute:"synopsis", value:
"A remote web application is vulnerable to cross site scripting." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running PhpGroupWare, is a multi-user groupware 
suite written in PHP.

This version is vulnerable to script injection, a malicious admin can inject
script code into the main screen message." );
 script_set_attribute(attribute:"solution", value:
"Update to version 0.9.16.007 or newer." );
 script_set_attribute(attribute:"see_also", value:"http://www.phpgroupware.org/" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 
 script_summary(english:"Checks for PhpGroupWare version");
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 David Maciejak");
 script_family(english:"CGI abuses : XSS");
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
if ( ereg(pattern:"^0\.([0-8]\.|9\.([0-9]\.|1[0-5]\.|16\.0[0-6]([^0-9]|$)))", string:matches[1]))
{
	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}
