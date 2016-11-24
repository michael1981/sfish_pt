#
#  (C) Tenable Network Security, Inc.
#

#  Ref: Carlos Ulver


include("compat.inc");

if(description)
{
 script_id(15864);
 script_version("$Revision: 1.10 $");
 script_cve_id("CVE-2004-1196", "CVE-2004-1197");
 script_bugtraq_id(11758);
 script_xref(name:"OSVDB", value:"12155");
 script_xref(name:"OSVDB", value:"12156");
 
 script_name(english:"InMail/InShop inmail.pl / inshop.pl XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a Perl application that is affected
by a cross-site scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is using InMail/InShop, a web applications written in
Perl.

An implementation error in the validation of the user input 
specifically in the script 'inmail.pl' in its 'acao' uri-argument and
'inshop.pl' in its 'screen' uri argument lead to an XSS vulnerability 
allowing a user to create cross site attacks, also allowing theft of 
cookie-based authentication credentials." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2004-11/0334.html" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 
 summary["english"] = "Checks XSS in InMail and InShop";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
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

if (report_paranoia < 2) exit(0);

port = get_http_port(default:80);

if (!can_host_php(port:port))exit(0);
if ( get_kb_item("www/" + port + "/generic_xss") ) exit ( 0 );

function check_dir(path)
{
 local_var	r;
 r = http_send_recv3(method: 'GET', item:string(path, "/inmail.pl?acao=<<script>foo</script>"), port:port);
 if (isnull(r)) exit(0);
 if (r[0] =~ "^HTTP/1\.[01] +200 " && "<script>foo</script>" >< r[2] )
 {
  security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  exit(0);
 }
 
 r = http_send_recv3(method: 'GET', item:string(path, "/inshop.pl?screen=<script>foo</script>"), port:port);
 if (isnull(r)) exit(0);

 if (r[0] =~ "^HTTP/1\.[01] +200 " && "<script>foo</script>" >< r[2] )
 {
  security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  exit(0);
 }
}

foreach dir ( cgi_dirs() )
{
 check_dir(path:dir);
}
 
