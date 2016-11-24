#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
#  Ref: Alexander Antipov <antipov SecurityLab ru> - MAxpatrol Security
#
#  This script is released under the GNU GPL v2

# Changes by Tenable:
# - Revised plugin title, added OSVDB refs, changed family (4/28/09)


include("compat.inc");

if(description)
{
 script_id(15451);
 script_version ("$Revision: 1.9 $");
 script_cve_id("CVE-2004-1588", "CVE-2004-1589");
 script_bugtraq_id(11361);
 script_xref(name:"OSVDB", value:"10641");
 script_xref(name:"OSVDB", value:"10642");
 script_xref(name:"OSVDB", value:"10643");
 script_xref(name:"OSVDB", value:"10644");

 script_name(english:"GoSmart Message Board Multiple Vulnerabilities (SQLi, XSS)");
 
 script_set_attribute(attribute:"synopsis", value:
"A remote CGI is vulnerable to several flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is running GoSmart message board, a bulletin board 
manager written in ASP.

The remote version of this software contains multiple flaws, due 
to a failure of the application to properly sanitize user-supplied input.

It is also affected by a cross-site scripting vulnerability. 
As a result of this vulnerability, it is possible for a remote attacker
to create a malicious link containing script code that will be executed 
in the browser of an unsuspecting user when followed. 

Furthermore, this version is vulnerable to SQL injection flaws that
let an attacker inject arbitrary SQL commands." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the newest version of this software" );
 script_set_attribute(attribute:"cvss_vector", value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_end_attributes();

 script_summary(english:"Checks GoSmart message board flaws");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"CGI abuses");
 script_dependencie("cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if (report_paranoia < 2) exit(0);

port = get_http_port(default:80);

if (!get_port_state(port))exit(0);
if ( ! can_host_asp(port:port) ) exit(0);
if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

foreach dir (cgi_dirs())
{
 req = string(dir, "/messageboard/Forum.asp?QuestionNumber=1&Find=1&Category=%22%3E%3Cscript%3Efoo%3C%2Fscript%3E%3C%22");
 req = http_get(item:req, port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if (egrep(pattern:"<script>foo</script>", string:r))
 {
       security_hole(port);
       set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
       set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
       exit(0);
 }
}
