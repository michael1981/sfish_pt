#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#


include("compat.inc");

if (description) {
  script_id(14379);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2004-1719", "CVE-2004-1720", "CVE-2004-1721", "CVE-2004-1722");
  script_bugtraq_id(10966);
  script_xref(name:"OSVDB", value:"9037");
  script_xref(name:"OSVDB", value:"9038");
  script_xref(name:"OSVDB", value:"9039");
  script_xref(name:"OSVDB", value:"9040");
  script_xref(name:"OSVDB", value:"9041");
  script_xref(name:"OSVDB", value:"9042");
  script_xref(name:"OSVDB", value:"9043");
  script_xref(name:"OSVDB", value:"9044");
  script_xref(name:"OSVDB", value:"9045");
  script_xref(name:"OSVDB", value:"15062");

  script_name(english:"Merak Webmail / IceWarp Web Mail 5.2.8 Multiple Vulnerabilties");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hsoting a webmail application that is 
affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The target is running at least one instance of Merak Webmail / IceWarp
Web Mail 5.2.7 or less or Merak Mail Server 7.5.2 or less.  Such 
versions are potentially affected by multiple XSS, HTML and SQL 
injection, and PHP source code disclosure vulnerabilities." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2004-08/0239.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Merak Webmail / IceWarp Web Mail 5.2.8 or Merak Mail Server
7.5.2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Checks for Multiple Vulnerabilities in Merak Webmail / IceWarp Web Mail";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2009 George A. Theall");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencie("global_settings.nasl", "http_version.nasl");
  script_require_ports("Services/www", 4096);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

host = get_host_name();
# nb: if webmail component installed, it's defaults to 4096;
#     if mail server, it's on 32000.
port = get_http_port(default:4096);

if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

# nb: software is accessible through either "/mail" (default) or "/".
dirs = make_list("/mail", "");
foreach dir (dirs) {

  # Try to retrieve inc/function.php since it's accessible in vulnerable versions.
  url = string(dir, "/inc/function.php");

  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if (res == NULL) exit(0);           # can't connect

  # Check the server signature as well as the content of the file retrieved.
  if (
    egrep(string:res, pattern:"^Server: IceWarp", icase:TRUE) &&
    egrep(string:res, pattern:"function getusersession", icase:TRUE)
  ) {
    security_hole(port:port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
