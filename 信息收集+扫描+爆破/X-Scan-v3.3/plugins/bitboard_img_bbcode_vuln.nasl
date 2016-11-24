#
# (C) Tenable Network Security, inc.
#


include("compat.inc");

if(description)
{
 script_id(16191);
 script_version("$Revision: 1.11 $");

 script_cve_id("CVE-2005-0374");
 script_bugtraq_id(12248);
 script_xref(name:"OSVDB", value:"12921");

 script_name(english:"BiTBOARD IMG BBCode Tag XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a cross-
site scripting attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running BiTBOARD, a web-based bulletin board
written in PHP. 

The remote version of this software is affected by a cross-site
scripting issue that may allow an attacker to steal the http cookies
of the regular users of the remote site to gain unauthorized access to
their account." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-01/0129.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to BiTBOARD 2.6 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N" );
script_end_attributes();

 
 script_summary(english:"Determines the version of BiTBOARD");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);

function check(url)
{
 local_var r, res;
 global_var port;

 r = http_send_recv3(port: port, method: 'GET', item: url +"/index.php");
 if (isnull(r)) exit(0);
 res = r[1] + r[2];
 if ( "the BiTSHiFTERS SDC" >< res )
 {
  if ( egrep(pattern:"BiTBOARD v([0.1]\..*|2\.[0-5]) Bulletin Board by.*the BiTSHiFTERS SDC</a>", string: res) ) {
	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	exit(0);
	}
 }
}

foreach dir ( cgi_dirs() )
{
  check(url:dir);
}
