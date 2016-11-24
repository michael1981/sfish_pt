#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(17336);
  script_version("$Revision: 1.9 $");

  script_bugtraq_id(12796);
  script_xref(name:"OSVDB", value:"14775");

  script_name(english:"paBox pabox.php posticon Parameter XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a cross-
site scripting attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running paBox, a web application written in PHP. 

The remote version of paBox installed on the remote host does not
properly sanitize input supplied through the 'posticon' parameter used
to select a 'smilie' for a post.  By exploiting this flaw, an attacker
can inject HTML and script code into the browser of users who view the
affected post, potentially stealing authentication cookies and
controlling how the affected application is rendered." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/393156" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 
  script_summary(english:"Checks for post icon HTML injection vulnerability in paBox");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses : XSS");
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_dependencies("cross_site_scripting.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# The exploit.
#
# nb: "alurt" rather than "alert" to not wreck havoc.
xss = '<script>alurt("Nessus");</script>';
# and the url-encoded version.
exss = "%22%3E%3Cscript%3Ealurt(%22Nessus%22)%3B%3C%2Fscript%3E";
foreach dir (cgi_dirs()) {
  # Try the exploit.
  postdata = string(
    "name=nasl&",
    "site=&",
    "shout=A%20test&",
    "posticon=", exss, "&",
    "submit=Shout!"
  );
  r = http_send_recv3(method: "POST", item: dir+"/pabox.php?action=add", 
 port: port, data: postdata,
 add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));
  if (isnull(r)) exit(0);

  # After posting, the page must be retrieved to see the results.
  if ('<META HTTP-EQUIV="Refresh"' >< r[2]) {
    r = http_send_recv3(method: "GET", item:string(dir, "/pabox.php"), port:port);
    if (isnull(r)) exit(0);

    # If we see our XSS, there's a problem.
    if (xss >< r[2]) {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      exit(0);
    }
  }
}
