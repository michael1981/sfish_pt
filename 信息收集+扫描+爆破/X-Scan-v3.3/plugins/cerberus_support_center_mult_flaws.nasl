#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20347);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2005-4427", "CVE-2005-4428");
  script_bugtraq_id(16062);
  script_xref(name:"OSVDB", value:"21988");
  script_xref(name:"OSVDB", value:"21989");
  script_xref(name:"OSVDB", value:"21990");
  script_xref(name:"OSVDB", value:"21991");
  script_xref(name:"OSVDB", value:"21992");
  script_xref(name:"OSVDB", value:"21993");
  script_xref(name:"OSVDB", value:"21994");
  script_xref(name:"OSVDB", value:"21995");

  script_name(english:"Cerberus Support Center Multiple Remote Vulnerabilities (SQLi, XSS)");
  script_summary(english:"Checks for multiple vulnerabilities in Cerberus Support Center");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server has a PHP application that is affected by SQL
injection and cross-site scripting flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Cerberus Support Center, a customer support
portal written in PHP. 

The installed version of Cerberus Support Center is affected by a
cross-site scripting flaw due to its failure to sanitize input to the
'kb_ask' parameter of the 'index.php' script before using it in
dynamically-generated web pages.  In addition, it reportedly fails to
sanitize input to the the 'file_id' parameter of the
'attachment_send.php' script before using it in database queries. 

Exploitation of the SQL injection vulnerability requires that an
attacker first authenticate while the cross-site scripting issue may
be possible without authentication, depending on the application's
configuration." );
 script_set_attribute(attribute:"see_also", value:"http://lists.grok.org.uk/pipermail/full-disclosure/2005-December/040324.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.cerberusweb.com/devblog/?p=56" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Cerberus Support Center 3.2.0pr2 and edit
'attachment_send.php' as described in the forum post referenced above. 
Note that this does not, though, fix the cross-site scripting issue." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);

# A simple alert.
xss = '<script>alert("' + SCRIPT_NAME + '")</script>';


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/support-center", "/support", cgi_dirs()));
else dirs = make_list(cgi_dirs());

# nb: the documentation uses 'support.php' when integrating the product
#     into Cerberus Help Desk, although the actual name is arbitrary.
if (thorough_tests) files = make_list("index.php", "support.php");
else files = make_list("index.php");

foreach dir (dirs) {
  foreach file (files) {
    # Try to exploit the XSS flaw.
    #
    # nb: we're SOL if authentication is required.
    r = http_send_recv3(method:"GET", port: port,
      item:string( dir, "/", file, "?",
        "mod_id=2&",  "kb_ask=", urlencode(str:string("</textarea>", xss))));
    if (isnull(r)) exit(0);
    res = r[2];

    # There's a problem if...
    if (
      # the result looks like the results of a KB search and...
      '<td class="box_content_text">' >< res &&
      # we see our XSS.
      string("</textarea>", xss) >< res
    ) {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
