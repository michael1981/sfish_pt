#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
# Ref: PhpGroupWare Team
# This script is released under the GNU GPLv2

# Changes by Tenable:
# - Revised plugin title (3/31/2009)


include("compat.inc");

if(description)
{
 script_id(14295);
 script_version ("$Revision: 1.9 $");
 script_cve_id("CVE-2004-0016");
 script_bugtraq_id(9387);
 script_xref(name:"OSVDB", value:"6860");

 script_name(english:"phpGroupWare Calendar Module Holiday File Save Extension Feature Arbitrary File Execution");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of PhpGroupware which is vulnerable
to a remote attack.

PhpGroupWare is a multi-user groupware suite written in PHP.

It has been reported that this version may be prone to a vulnerability 
that may allow remote attackers to execute malicious scripts on a 
vulnerable system. 
The flaw allows remote attackers to upload server side scripts which can
then be executed on the server." );
 script_set_attribute(attribute:"solution", value:
"Update to version 0.9.14.007 or newer" );
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

port = get_http_port(default:80);

kb = get_kb_item("www/" + port + "/phpGroupWare");
if (! kb ) exit(0);
matches = eregmatch(pattern:"(.*) under (.*)", string:kb);

if ( ereg(pattern:"^0\.([0-8]\.|9\.([0-9]\.|1[0-3]\.|14\.0*[0-6]([^0-9]|$)))", string:matches[1]) )
	security_hole(port);
