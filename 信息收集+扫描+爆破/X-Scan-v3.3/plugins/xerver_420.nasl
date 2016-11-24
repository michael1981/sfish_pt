#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20062);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2005-3293", "CVE-2005-4774");
  script_bugtraq_id(15135);
  script_xref(name:"OSVDB", value:"20075");
  script_xref(name:"OSVDB", value:"20076");
  script_xref(name:"OSVDB", value:"20077");

  script_name(english:"Xerver < 4.20 Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in Xerver < 4.20");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Xerver, an open-source FTP and web server
written in Java. 

The version of Xerver installed on the remote host suffers from
several vulnerabilities that can be used by an attacker to reveal the
contents of directories as well as the source of scripts and HTML
pages.  In addition, it is prone to a generic cross-site scripting
flaw." );
 script_set_attribute(attribute:"see_also", value:"http://securitytracker.com/alerts/2005/Oct/1015079.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Xerver 4.20 or later as that is rumoured to address the
issue." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80);


# Unless we're paranoid, make sure the banner looks like Xerver.
if (report_paranoia < 2) {
  banner = get_http_banner(port:port);
  if (!banner || "Server: Xerver" >!< banner) exit(0);
}


# Get the initial page.
#
# nb: Xerver doesn't deal nicely with http_keepalive_send_recv() for 
#     some reason so we don't use it below.
res = http_get_cache(item:"/", port:port);
if (res == NULL) exit(0);


# If that's a directory listing...
if ("<TITLE>Directory Listing" >< res) {
  if (!get_kb_item("www/" + port + "/generic_xss")) {
    # Try to exploit the XSS flaw.
    xss = "<script>alert('" + SCRIPT_NAME + "')</script>";
    r = http_send_recv3(method:"GET", item:raw_string("/%00/", urlencode(str:xss), "/"), port:port);
    if (isnull(r)) exit(0);
    res = r[2];
    # There's a problem if we see our XSS.
    if (
      "<TITLE>Directory Listing" >< res && 
      xss >< res
    ) {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    }
  }
}
# Otherwise...
else {
  # Try to force a directory listing.
  r = http_send_recv3(method: "GET", item:"/%00/", port:port);
  if (isnull(r)) exit(0);
  res = r[2];
  # There's a problem if we now get a directory listing.
  if ("<TITLE>Directory Listing" >< res) {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
