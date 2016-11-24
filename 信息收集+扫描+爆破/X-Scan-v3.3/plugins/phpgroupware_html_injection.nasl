#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
# Ref: François SORIN <francois.sorin@security-corporation.com>
# This script is released under the GNU GPLv2


include("compat.inc");

if(description)
{
 script_id(14292);
 script_version ("$Revision: 1.9 $");
 script_cve_id("CVE-2003-0504");
 script_bugtraq_id(8088);
 script_xref(name:"OSVDB", value:"2243");

 script_name(english:"phpGroupWare index.php Addressbook XSS");

 script_set_attribute(attribute:"synopsis", value:
"A remote web application is vulnerable to multiple cross site scripting 
attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running PhpGroupWare, is a multi-user 
groupware suite written in PHP.

This version has been reported prone to multiple HTML injection 
vulnerabilities. 
The issues present themselves due to a lack of sufficient input 
validation performed on form fields used by PHPGroupWare modules. 

A malicious attacker may inject arbitrary HTML and script code using 
these form fields that may be incorporated into dynamically generated 
web content." );
 script_set_attribute(attribute:"solution", value:
"Update to version 0.9.14.005 or newer" );
 script_set_attribute(attribute:"see_also", value:"http://www.phpgroupware.org/" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

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
if ( ! kb ) exit(0);

matches = eregmatch(pattern:"(.*) under (.*)", string:kb);
if ( ereg(pattern:"^0\.([0-8]\.|9\.([0-9]\.|1[0-3]\.|14\.0*[0-3]([^0-9]|$)))", string:matches[1]))
 			security_warning(port);
