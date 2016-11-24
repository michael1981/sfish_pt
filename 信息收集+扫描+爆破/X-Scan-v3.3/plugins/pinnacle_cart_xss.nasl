#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
  script_id(18038);
  script_version("$Revision: 1.7 $");
  script_cve_id("CVE-2005-1130");
  script_bugtraq_id(13138);
  script_xref(name:"OSVDB", value:"15485");

  script_name(english:"Pinnacle Cart index.php pg Parameter XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web application is vulnerable to cross site scripting." );
 script_set_attribute(attribute:"description", value:
"The remote host runs Pinnacle Cart, a shopping cart software written
in PHP.

The remote version of this software is vulnerable to cross-site
scripting attacks due to a lack of sanity checks on the 'pg' parameter
in the script 'index.php'." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Pinnacle Cart 3.3 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();


  script_summary(english:"Checks XSS in Pinnacle Cart");
  script_category(ACT_GATHER_INFO);
  
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses : XSS");
  script_dependencie("cross_site_scripting.nasl"); 
  script_require_ports("Services/www", 80);
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

test_cgi_xss( port: port, cgi: "index.php", 
 qs: "p=catalog&parent=42&pg=<script>foo</script>",
 pass_re: '<input type="hidden" name="backurl" value=".*/index\\.php?p=catalog&parent=42&pg=<script>foo</script>');
