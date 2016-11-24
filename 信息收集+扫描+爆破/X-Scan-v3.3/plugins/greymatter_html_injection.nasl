#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(16120);
 script_version ("$Revision: 1.9 $");
 script_bugtraq_id(12189,12182,12184);
 script_xref(name:"OSVDB", value:"12827");
 script_xref(name:"OSVDB", value:"12828");
 script_xref(name:"OSVDB", value:"12829");

 script_name(english:"Greymatter 1.3 Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a Perl application that is affected by an
HTML injection vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Greymatter, a web based log and journal 
maintenance system implemented in Perl. 

The remote version of this software is vulnerable to an HTML injection
attack due to a lack of filtering on user-supplied input in the file
'gm-comments.cgi'.  An attacker may exploit this flaw to perform a
cross-site scripting attack against the remote host. 

This software may be affected by another HTLM injection vulnerability
in the file 'gm-cplog.cgi' and to a password disclosure vulnerability
in the file 'gm-token.cgi'." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2005-01/0281.html" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
 script_end_attributes();

 script_summary(english:"Checks for the version of Greymatter");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port)) exit(0);

function check(url)
{
local_var req, r;
r = http_send_recv3(method:"GET", item:string(url, "/cgi-bin/gm-comments.cgi"), port:port);
if ( r == NULL ) exit(0);
if ( egrep(pattern:">v[0-1](\.[0-2]([0-9])?(\.[0-9])?)?|(\.3(\.0)?)?(a|b|c|d)?\s*&#183;\s*&copy;(19[0-9][0-9]|200[0-5])-(19[0-9][0-9]|200[0-5])(.*?)Greymatter|Noah\sGrey(.*?)<", string:r[2]))
 {
 security_warning(port);
 set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
 exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check(url:dir);
}
