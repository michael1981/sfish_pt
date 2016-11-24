#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
#  Ref: Espen Andersson
#
#  This script is released under the GNU GPL v2
#

# Changes by Tenable:
# - Revised plugin title (5/21/09)


include("compat.inc");

if(description)
{
 script_id(15392);
 script_version("$Revision: 1.10 $");
 script_xref(name:"OSVDB", value:"10348");
 
 script_name(english:"PHP-Fusion homepage address Parameter XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to cross-
site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"A vulnerability exists in the remote version of PHP-Fusion that may
allow an attacker to execute arbitrary HTML and script code in the
context of the user's browser." );
 script_set_attribute(attribute:"solution", value:
"Apply the patch for 4.01." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 script_summary(english:"Checks the version of the remote PHP-Fusion");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("php_fusion_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

kb = get_kb_item("www/" + port + "/php-fusion");
if ( ! kb ) exit(0);

items   = eregmatch(pattern:"(.*) under (.*)", string:kb);
version =  items[1];

if ( ereg(pattern:"([0-3][.,]|4[.,]0[01]([^0-9]|$))", string:version) )
{
	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}
