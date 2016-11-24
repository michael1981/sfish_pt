#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(19776);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2005-3101", "CVE-2005-3102", "CVE-2005-3103", "CVE-2005-3104");
  script_bugtraq_id(14910, 14911, 14912);
  script_xref(name:"OSVDB", value:"19601");
  script_xref(name:"OSVDB", value:"19602");
  script_xref(name:"OSVDB", value:"19603");
  script_xref(name:"OSVDB", value:"19604");

  name["english"] = "Movable Type < 3.2 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains CGI scripts that are prone to arbitrary
remote command execution, information disclosure, and cross-site
scripting attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Movable Type, a blog software written in
Perl. 

The installed version of Movable Type allows an attacker to enumerate
valid usernames because its password reset functionality returns
different errors depending on whether the supplied username exists;
allows privileged users to upload files with arbitrary extensions,
possibly outside the web server's document directory; and fails to
sanitize certain fields when creating new blog entries of malicious
HTML and script code before using them to generate dynamic web pages." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2005-11/0091.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Movable Type 3.2 or later and grant only trusted users the
ability to upload files via the administrative interface." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Checks for multiple vulnerabilities in Movable Type < 3.2";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);


# Loop through CGI directories.
if (thorough_tests) dirs = list_uniq(make_list("/mt", "/cgi-bin/mt", "/blog", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (cgi_dirs()) {
  # Try to find Movable Type.
  req = http_get(item:"/mt.cgi", port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (isnull(res)) exit(0);

  # Do a banner check.
  if (
    '<div id="copyright">' >< res &&
    egrep(
      string:res, 
      pattern:"^<b>Version ([0-2]\..*|3\.[01].*)</b> Copyright &copy; .+ Six Apart"
    )
  ) {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
