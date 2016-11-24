#
#       This script was written by Justin Seitz <jms@bughunter.ca>
#       Per Justin : GPLv2
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB refs, revamped desc to cover multiple scripts (4/28/09)
# - Replaced broken link (5/29/09)



include("compat.inc");

if(description)
{
 # set script identifiers

 script_id(23775);
 script_version("$Revision: 1.10 $");
 script_bugtraq_id(21233);
 script_xref(name:"OSVDB", value:"30658");
 script_xref(name:"OSVDB", value:"30659");
 script_xref(name:"OSVDB", value:"54105");
 script_xref(name:"OSVDB", value:"54106");

 script_name(english:"CuteNews 1.4.5 Multiple Script XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains PHP scripts that is affected by a
cross-site scripting issue." );
 script_set_attribute(attribute:"description", value:
"The version of CuteNews installed on the remote host fails to sanitize
input to the 'index.php', 'search.php', 'rss.php' and 'show_news.php' 
scripts before using it to generate dynamic HTML to be returned to the 
user.  An unauthenticated attacker can exploit these issues to execute a 
cross-site scripting attack. 

This version of CuteNews is also likely affected by other associated
issues." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2006-11/0419.html" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 script_summary(english:"Tries to inject javascript code.");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2006-2009 Justin Seitz");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("cutenews_detect.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");


port = get_http_port(default:80);

#
# verify we can talk to the web server, if not exit
#

if(!get_port_state(port)) exit(0);
if(!can_host_php(port:port)) exit(0);
if (get_kb_item("www/" + port + "/generic_xss")) exit(0);

#
#
#	Test for an install of Cutenews
#
#

install = get_kb_item(string("www/", port, "/cutenews"));
if (isnull(install)) exit(0);

matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
	  dir = matches[2];
	  attackstring = '"><script>alert(document.cookie)</script>';
          attacksploit = urlencode(str:attackstring, unreserved : "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_!~*'()-]/");
          attackreq = http_get(item:string(dir, "/search.php/", attacksploit), port:port);
          attackres = http_keepalive_send_recv(port:port, data:attackreq, bodyonly:TRUE);
          if(isnull(attackres)) exit(0);
	  if(string('action="', dir, "/search.php/", attackstring, "?subaction=search") >< attackres)
	  {
		security_warning(port);
		set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	  }
}
