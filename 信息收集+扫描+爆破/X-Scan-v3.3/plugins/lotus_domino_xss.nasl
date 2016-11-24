#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# 
# This script is released under the GNU GPL v2
#

# Changes by Tenable:
# - Revised plugin title (4/30/09)


include("compat.inc");

if(description)
{
  script_id(19764);
  script_version("$Revision: 1.9 $");
  script_cve_id("CVE-2005-3015");
  script_bugtraq_id(14845, 14846);
  
  script_name(english:"Lotus Domino Multiple Script Src / BaseTarget XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to cross-site scripting issues." );
 script_set_attribute(attribute:"description", value:
"The remote host runs Lotus Domino web server.

The installed version of Lotus Domino is vulnerable to multiple cross-
site scripting attacks due to a lack of sanitization of user-supplied
data.  Successful exploitation of this issue may allow an attacker to
execute malicious script code in a user's browser within the context
of the affected application." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Domino 6.5.2 or newer" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

  script_summary(english:"Checks Lotus Domino XSS");
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2005-2009 David Maciejak");
  script_family(english:"CGI abuses : XSS");
  script_require_ports("Services/www", 80);
  script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
  exit(0);
}

#the code

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if(!banner)exit(0);
if ( "Lotus" >!< banner ) exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

buf = http_get(item:"/", port:port);
r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
if( r == NULL )exit(0);

matches = egrep(pattern:'src=.+(.+?OpenForm.+BaseTarget=)', string:r);
foreach match (split(matches)) 
{
       match = chomp(match);
       matchspec=eregmatch(pattern:'src="(.+?OpenForm.+BaseTarget=)', string:match);
       if (!isnull(matchspec))
       {
	       buf = http_get(item:string(matchspec[1],'";+<script>alert(foo)</script>;+var+mit="a'), port:port);
	       r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
	       if( r == NULL )exit(0);

	       if ("<script>alert(foo)</script>" >< r)
	       {
		       security_warning(port);
		       set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	       }
       }
}
exit(0);
