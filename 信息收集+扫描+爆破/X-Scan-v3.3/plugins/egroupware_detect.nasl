#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(15720);
 script_version("$Revision: 1.6 $");
 
 script_name(english:"EGroupware Software Detection");
 script_summary(english:"Detects the presence of EGroupWare");

 script_set_attribute(
   attribute:"synopsis",
   value:"A groupware server written in PHP is running on the remote host."
 );
 script_set_attribute(
   attribute:"description", 
   value:"The remote host is running eGroupware, a web-based groupware solution."
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.egroupware.org/"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"n/a"
 );
 script_set_attribute(
   attribute:"risk_factor", 
   value:"None"
 );
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 exit(0);
}

#
# The script code starts here
#


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port))
  exit(0, "The web server isn't capable of hosting PHP applications.");

dirs = "";

function check(loc)
{
 local_var url, r, version_str, version;

 url = string(loc, "/login.php");
 r = http_send_recv3(method:"GET", item:url, port:port);
 if (isnull(r)) exit(1, "The web server didn't respond to the GET request.");

 # Check the response body
 r = r[2];
 if('eGroupWare' >< r && egrep(pattern:"<a href=.*www\.egroupware\.org.*eGroupWare</a> ([0-9.])*", string:r) ) 
 {
	version_str = egrep(pattern:".*www.egroupware.org.*eGroupWare</a> ([0-9.]*)</div>.*", string:r);
	version_str = chomp(version_str);
 	version = ereg_replace(pattern:".*www.egroupware.org.*eGroupWare</a> ([0-9.]*)</div>", string:version_str, replace:"\1");
	if ( loc == "" ) loc = "/";
	set_kb_item(name:"www/" + port + "/egroupware",
		    value:version + " under " + loc );
	
	dirs += loc + '\n';
 }
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
}

if (dirs) 
{
report = "
EGroupWare is installed under the following location(s) :
" + dirs + "
";
 security_note(port:port, extra:report);
}
