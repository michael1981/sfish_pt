#
# This script was written by Josh Zlatin-Amishav <josh at tkos dot co dot il>
# This script is released under the GNU GPLv2
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB refs (4/28/09)

include("compat.inc");

if(description)
{
  script_id(18505);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2005-0040");
  script_bugtraq_id(13644, 13646, 13647);
  script_xref(name:"OSVDB", value:"16614");
  script_xref(name:"OSVDB", value:"16615");
  script_xref(name:"OSVDB", value:"16616");

  script_name(english:"DotNetNuke < 3.0.12 Multiple XSS");
  script_summary(english:"Checks version of DotNetNuke");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an ASP application that is affected by
multiple input validation flaws.");
  script_set_attribute(attribute:"description", value:
"The remote host is running DotNetNuke, a portal written in ASP. 

The remote installation of DotNetNuke, according to its version
number, contains several input validation flaws leading to the
execution of attacker supplied HTML and script code.");
  script_set_attribute(attribute:"see_also", value:
"http://archives.neohapsis.com/archives/bugtraq/2005-05/0198.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 3.0.12 or later.");
  script_set_attribute(attribute:"cvss_vector", value:
"CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_attribute(attribute:"plugin_publication_date", value:
"2005/06/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Copyright (C) 2005-2009 Josh Zlatin-Amishav");
  script_family(english:"CGI abuses : XSS");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencie("http_version.nasl");
  exit(0);
}

# the code!

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_asp(port:port))exit(0);

function check(url)
{
 local_var req, res;
 global_var port;

 req = http_get(item:url +"/default.aspx", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( isnull(res) ) exit(0);

 if ( 'DotNetNukeAnonymous' >< res && egrep(pattern:"\( DNN (2\.0\.|2\.1\.[0-4]|3\.0\.([0-9]|1[0-1] \)))", string:res) )
 {
        security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
        exit(0);
 }
}


foreach dir ( cgi_dirs() ) check(url:dir);
