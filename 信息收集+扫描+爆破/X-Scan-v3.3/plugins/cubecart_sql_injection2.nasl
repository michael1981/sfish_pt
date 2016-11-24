#
# (C) Tenable Network Security
#

include("compat.inc");

if (description) {
  script_id(17999);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2005-1033");
  script_bugtraq_id(13050);
  script_xref(name:"OSVDB", value:"15315");
  script_xref(name:"OSVDB", value:"15316");
  script_xref(name:"OSVDB", value:"15317");
  script_xref(name:"OSVDB", value:"15318");

  script_name(english:"CubeCart <= 2.0.6 Multiple SQL Injections");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is vulnerable to
SQL injection attacks." );
 script_set_attribute(attribute:"description", value:
"The installed version of CubeCart on the remote host suffers from
multiple SQL injection vulnerabilities due to its failure to sanitize
user input via the 'PHPSESSID' parameter of the 'index.php' script,
the 'product' parameter of the 'tellafriend.php' script, the 'add'
parameter of the 'view_cart.php' script, and the 'product' parameter
of the 'view_product.php' script.  An attacker can take advantage of
these flaws to manipulate database queries." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-04/0083.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to CubeCart 2.0.7 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Checks for multiple SQL injection vulnerabilities in CubeCart 2.0.6 and earlier";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  family["english"] = "CGI abuses";
  script_family(english:family["english"]);
 
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("cubecart_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# These exploits should just generate syntax errors.
exploits = make_list(
  "/index.php?PHPSESSID='",
  "/tellafriend.php?product='",
  "/view_cart.php?add='",
  "/view_product.php?product='"
);


# Test an install.
install = get_kb_item(string("www/", port, "/cubecart"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  foreach exploit (exploits) {
    r = http_send_recv3(method:"GET", item:string(dir, exploit), port:port);
    if (isnull(r)) exit(0);
    res = r[2];

    # There's a problem if we see an error.
    if (egrep(string:res, pattern:"<b>Warning</b>: .+ in <b>.+\.php</b> on line"))
    {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
