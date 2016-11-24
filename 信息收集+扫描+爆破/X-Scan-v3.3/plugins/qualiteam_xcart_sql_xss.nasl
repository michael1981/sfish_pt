#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(18419);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2005-1822", "CVE-2005-1823");
  script_bugtraq_id(13817);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"16936");
    script_xref(name:"OSVDB", value:"16937");
    script_xref(name:"OSVDB", value:"16938");
    script_xref(name:"OSVDB", value:"16939");
    script_xref(name:"OSVDB", value:"16940");
    script_xref(name:"OSVDB", value:"16941");
    script_xref(name:"OSVDB", value:"16942");
    script_xref(name:"OSVDB", value:"16943");
    script_xref(name:"OSVDB", value:"16944");
    script_xref(name:"OSVDB", value:"16945");
    script_xref(name:"OSVDB", value:"16946");
    script_xref(name:"OSVDB", value:"16947");
    script_xref(name:"OSVDB", value:"16948");
    script_xref(name:"OSVDB", value:"16949");
    script_xref(name:"OSVDB", value:"16950");
    script_xref(name:"OSVDB", value:"16951");
  }

  script_name(english:"Qualiteam X-Cart Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application affected by several
flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is running X-Cart, a PHP-based shopping cart system. 

The version installed on the remote host suffers from numerous SQL
injection and cross-site scripting vulnerabilities.  Attackers can
exploit the former to influence database queries, resulting possibly
in a compromise of the affected application, disclosure of sensitive
data, or even attacks against the underlying database.  And
exploitation of the cross-site scripting flaws can be used to steal
cookie-based authentication credentials and perform similar attacks." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/401035/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  script_summary(english:"Checks for multiple vulnerabilities in X-Cart");
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

init_cookiejar();
erase_http_cookie(name: "xid");

# For each CGI directory...
foreach dir (cgi_dirs()) {
  # Try to exploit one of the SQL flaws.
  r = http_send_recv3(method: "GET",
    item:string(dir, "/help.php?section='", SCRIPT_NAME),
    port:port
  );
  if (isnull(r)) exit(0);

  # If ...
  if (
    # it looks like X-Cart and...
    ! isnull(get_http_cookie(name: "xid")) &&
    egrep(string: r[2], pattern:"^<!-- /?central space -->") &&
    # we get a syntax error.
    egrep(string: r[2], pattern:string("SELECT pageid FROM xcart_stats_pages WHERE page='/cart/help\.php\?section='", SCRIPT_NAME))
  ) {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
