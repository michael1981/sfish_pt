#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(30055);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2008-0782");
  script_bugtraq_id(27404);
  script_xref(name:"milw0rm", value:"4957");
  script_xref(name:"OSVDB", value:"41780");

  script_name(english:"MoinMoin MOIN_ID Cookie userform Action Traversal Arbitrary File Overwrite");
  script_summary(english:"Tries to generate an error using an invalid cookie");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Python application that suffers from
an input sanitation vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running MoinMoin, a wiki application written in
Python. 

The version of MoinMoin installed on the remote host fails to validate
input to the 'MOIN_ID' cookie before using it to read and write user
profiles.  By providing the name of a file that exists on the remote
host and is writable by the web server user id, an unauthenticated
remote attacker may be able to exploit this issue to corrupt files,
possibly even injecting arbitrary PHP code that could later be
executed subject to the privileges of the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://hg.moinmo.in/moin/1.5/rev/e69a16b6e630" );
 script_set_attribute(attribute:"solution", value:
"Apply the patches referenced in the project's advisory above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/moinmoin", "/wiki", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  if (strlen(dir) == 0) dir = "/";
  # Pass in an invalid cookie.
  set_http_cookie(name: "MOIN_ID", value: ".");
  r = http_send_recv3(method: "GET", item:dir, port:port);
  if (isnull(r)) exit(0);

  # There's a problem if there's an error related to the cookie.
  if (
    '>IOError<' >< r[2] && '>[Errno 21]' >< r[2] &&
    "auth_method='moin_cookie'" >< r[2] && '/MoinMoin/user.py' >< r[2]
  )
  {
    security_hole(port);
    exit(0);
  }
}
