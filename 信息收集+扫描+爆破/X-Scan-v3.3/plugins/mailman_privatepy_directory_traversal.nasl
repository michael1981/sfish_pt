#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

# Changes by Tenable:
# - Revised plugin title, OSVDB ref, family change (9/5/09)
 

include("compat.inc");

if (description) {
  script_id(16339);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2005-0202");
  script_bugtraq_id(12504);
  script_xref(name:"OSVDB", value:"13671");
 
  script_name(english:"Mailman private.py true_path Function Traversal Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"Authenticated Mailman users can view arbitrary files on the remote
host." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the remote installation of Mailman
reportedly is prone to a directory traversal vulnerability in
'Cgi/private.py'.  The flaw comes into play only on web servers that
don't strip extraneous slashes from URLs, such as Apache 1.3.x, and
allows a list subscriber, using a specially crafted web request, to
retrieve arbitrary files from the server - any file accessible by the
user under which the web server operates, including email addresses
and passwords of subscribers of any lists hosted on the server.  For
example, if '$user' and '$pass' identify a subscriber of the list
'$listname@$target', then the following URL :

  
http://$target/mailman/private/$listname/.../....///mailman?username=$user&password=$pass

allows access to archives for the mailing list named 'mailman' for
which the user might not otherwise be entitled." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2005-02/0109.html" );
 script_set_attribute(attribute:"see_also", value:"http://mail.python.org/pipermail/mailman-announce/2005-February/000076.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mailman 2.1.6b1 or apply the fix referenced in the first
URL above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:S/C:P/I:N/A:N" );

script_end_attributes();

  script_summary(english:"Checks for Mailman private.py Directory Traversal Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2009 George A. Theall");
  script_dependencie("mailman_detect.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);

# Web servers to ignore because it's known they strip extra slashes from URLs.
#
# nb: these can be regex patterns.
web_servers_to_ignore = make_list(
  "Apache(-AdvancedExtranetServer)?/2",                      # Apache 2.x
  'Apache.*/.* \\(Darwin\\)'
);

# Skip check if the server's type and version indicate it's not a problem,
# unless report paranoia is set high.
banner = get_http_banner(port: port);
if (banner && report_paranoia < 2) {
  web_server = strstr(banner, "Server:");
  if (web_server) {
    web_server = web_server - "Server: ";
    web_server = web_server - strstr(web_server, '\r');
    foreach pat (web_servers_to_ignore) {
      if (ereg(string:web_server, pattern:pat)) {
        debug_print("skipping because web server claims to be '", web_server, "'.");
        exit(0);
      }
    }
  }
}


# Test an install.
install = get_kb_item(string("www/", port, "/Mailman"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^2\.(0.*|1($|[^0-9.]|\.[1-5]($|[^0-9])))") {
    security_note(port);
  }
}
