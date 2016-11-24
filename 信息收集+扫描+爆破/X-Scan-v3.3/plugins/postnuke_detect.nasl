#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(15721);
 script_version("$Revision: 1.8 $");
 
 script_name(english:"PostNuke Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP-based content management system." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PostNuke, a content manager system written
in PHP." );
 script_set_attribute(attribute:"see_also", value:"http://www.postnuke.com/" );
 script_set_attribute(attribute:"solution", value:"N/A");
 script_set_attribute(attribute:"risk_factor", value:"None" );
script_end_attributes();

 
 summary["english"] = "Detects the presence of PostNuke";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "webmirror.nasl");
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
if(!can_host_php(port:port))exit(0);

dirs = "";




function check(loc)
{
 local_var r, w, version, version_str;

 w = http_send_recv3(method:"GET", item:string(loc, "/index.php?module=Navigation"), port:port);
 if (isnull(w)) exit(0, "the web server did not answer");
 r = w[2];
 if('PostNuke' >< r && egrep(pattern:"<meta name=.generator. content=.PostNuke", string:r, icase:1) )
 {
	version_str = egrep(pattern:"<meta name=.generator. content=.PostNuke", string:r, icase:1);
	version_str = chomp(version_str);
 	version = ereg_replace(pattern:".*content=.PostNuke ([0-9.]*) .*", string:version_str, replace:"\1");
	if ( version == version_str ) version = "unknown";
	if ( loc == "" ) loc = "/";
	set_kb_item(name:"www/" + port + "/postnuke",
		    value:version + " under " + loc );
	
	dirs += "  - " + version + " under '" + loc + "'\n";
 }
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
 if (dirs && !thorough_tests) break;
}

if ( dirs ) 
{
  info = string(
    "\n",
    "The following version(s) of PostNuke were detected :\n",
    "\n",
    dirs
  );
  security_note(port:port, extra:info);
}

