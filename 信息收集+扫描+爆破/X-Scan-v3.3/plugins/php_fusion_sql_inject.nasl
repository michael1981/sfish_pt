#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
#  Ref: r0ut3r
#
#  This script is released under the GNU GPL v2
#
# Changes by Tenable:
#   - added CVE and additional OSVDB xrefs.
#   - plugin title update (3/30/2009)


include("compat.inc");

if(description)
{
 script_id(15433);
 script_version("$Revision: 1.12 $");
 script_cve_id("CVE-2004-2437", "CVE-2004-2438");
 script_bugtraq_id(11296, 12425);
 script_xref(name:"OSVDB", value:"10437");
 script_xref(name:"OSVDB", value:"10438");
 script_xref(name:"OSVDB", value:"10439");
 
 script_name(english:"PHP-Fusion 4.01 Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains several PHP scripts that suffer from
multiple flaws." );
 script_set_attribute(attribute:"description", value:
"A vulnerability exists in the remote version of PHP-Fusion that may
allow an authenticated attacker to inject arbitrary SQL code due to
improper validation of user-supplied input to the 'rowstart' parameter
of script 'members.php' and the 'comment_id' parameter of the
'comments.php' script. 

In addition to this, the remote version of this software also contains
several cross-site scripting issues as well as an information
disclosure vulnerability." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P" );

script_end_attributes();

 
 summary["english"] = "Checks the version of the remote PHP-Fusion";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"CGI abuses");
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
items = eregmatch(pattern:"(.*) under (.*)", string:kb);
version = items[1];

if ( ereg(pattern:"^([0-3][.,]|4[.,]0[01]([^0-9]|$))", string:version) )
{
	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
}
