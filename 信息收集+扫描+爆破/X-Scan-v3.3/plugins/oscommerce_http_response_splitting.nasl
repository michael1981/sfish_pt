#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18525);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2005-1951");
  script_bugtraq_id(13979);
  script_xref(name:"OSVDB", value:"17284");

  script_name(english:"osCommerce application_top.php Multiple Parameter HTTP Response Splitting");
  script_summary(english:"Checks for multiple HTTP response splitting vulnerabilities in osCommerce");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is susceptible
to multiple HTTP Response splitting attacks." );
  script_set_attribute(attribute:"description", value:
"The version of osCommerce on the remote host suffers from multiple
HTTP response splitting vulnerabilities due to its failure to sanitize
user-supplied input to various parameters of the
'includes/application_top.php' script, the 'goto' parameter of the
'banner.php' script, and possibly others.  An attacker may be able to
exploit these flaws to inject malicious text into HTTP headers,
possibly resulting in the theft of session identifiers and/or
misrepresentation of the affected site." );
  script_set_attribute(attribute:"see_also", value:"http://www.gulftech.org/?node=research&article_id=00080-06102005" );
  script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-06/0068.html" );
  script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
  script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
  script_end_attributes();
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("oscommerce_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0, "The web server on port "+port+" does not support PHP scripts.");


# Test an install.
install = get_install_from_kb(appname:'oscommerce', port:port);
if (isnull(install)) exit(1, "osCommerce wasn't detected on port "+port+".");
dir = install['dir'];


# Grab the main page.
res = http_get_cache(item:string(dir, "/index.php"), port:port);
if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");


# Identify a product.
pat = '/product_info\\.php\\?products_id=([^&"]+)';
matches = egrep(pattern:pat, string:res);
id = NULL;

if (matches)
{
  foreach match (split(matches, keep:FALSE))
  {
    id = eregmatch(pattern:pat, string:match);
    if (!isnull(id))
    {
      id = id[1];
      break;
    }
  }
}
if (isnull(id)) exit(1, "Failed to identify a product in the osCommerce install at "+build_url(port:port, qs:dir+"/")+".");


# Try an exploit. A vulnerable application will output 
# a redirect along with our own redirect.
url = string(
  dir, "/index.php?",
  "action=buy_now&",
  "products_id=22=%0d%0aLocation:%20http://127.0.0.1/index.php?script=", SCRIPT_NAME
);

res = http_send_recv3(port:port, method:"GET", item:url);
if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

hdrs = parse_http_headers(status_line:res[0], headers:res[1]);
if (isnull(hdrs['$code'])) code = 0;
else code = hdrs['$code'];

if (isnull(hdrs['location'])) location = "";
else location = hdrs['location'];

# There's a problem if we're redirected to our script name.
if (code == 302 && string("127.0.0.1/index.php?script=", SCRIPT_NAME) >< location)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  security_warning(port);
  exit(0);
}
else exit(0, "The osCommerce install at "+build_url(port:port, qs:dir+"/")+" is not affected.");
