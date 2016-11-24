#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
# Ref: Cedric Cochin <cco@netvigilance.com>
# This script is released under the GNU GPLv2
#


include("compat.inc");

if(description)
{
 script_id(16138);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2004-2574");
 script_bugtraq_id(12082);
 script_xref(name:"OSVDB", value:"7599");
 script_xref(name:"OSVDB", value:"7600");
 script_xref(name:"OSVDB", value:"7601");
 script_xref(name:"OSVDB", value:"7602");
 script_xref(name:"OSVDB", value:"7603");
 script_xref(name:"OSVDB", value:"7604");

 script_name(english:"phpGroupWare index.php Calendar Date XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
several cross-site scripting vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of PhpGroupWare on the remote host has been reported prone
to HTML injection vulnerabilities through 'index.php'.  These issues
present themself due to a lack of sufficient input validation
performed on form fields used by PHPGroupWare modules. 

A malicious attacker may exploit these issues to inject arbitrary HTML
and script code using these form fields that then may be incorporated
into dynamically generated web content." );
 script_set_attribute(attribute:"see_also", value:"https://savannah.gnu.org/bugs/?func=detailitem&item_id=7478" );
 script_set_attribute(attribute:"solution", value:
"Update to version 0.9.16 RC3 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 
 summary["english"] = "Checks for PhpGroupWare version";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 David Maciejak");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("phpgroupware_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# the code
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


foreach d ( cgi_dirs() )
{
 req = http_get(item:string(d, "/phpsysinfo/inc/hook_admin.inc.php"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);

 if(egrep(pattern:".*Fatal error.* in <b>/.*", string:res)){
        security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
        exit(0);
 }
}
