#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(16322);
  script_version ("$Revision: 1.5 $");
  script_bugtraq_id(12438);
  script_xref(name:"OSVDB", value:"13450");

  script_name(english:"SunShop Shopping Cart index.php search Parameter XSS");
  script_summary(english:"Checks if SunShop Shopping Cart is installed");

   script_set_attribute(
    attribute:'synopsis',
    value:'The remote web application is vulnerable to cross site scripting.'
  );

  script_set_attribute(
    attribute:'description',
    value:'The remote host is running SunShop, a web-based shopping cart
written in PHP.

The remote version of this software is vulnerable to several input
validation flaws, which may allow an attacker to use the remote web
site to perform a cross site scripting attack.'
  );

  script_set_attribute(
    attribute:'solution',
    value:'Upgrade to SunShop version 3.5 or later.'
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://www.turnkeywebtools.com/index.php/location/products/product/sunshop/sub/overview/'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N'
  );

  script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port)) exit(0);
if(!can_host_php(port:port)) exit(0);

foreach dir ( cgi_dirs() )
{
 req = http_get(item:dir + "/index.php?search=<script>foo</script>", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if('<input type="text" name="search" size="10" class="input_box" value="<script>foo</script>">' >< res )
  {
  security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  exit(0);
  }
}
