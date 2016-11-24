#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(35749);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2009-0499");
  script_bugtraq_id(33615);
  script_xref(name:"Secunia", value:"33775");
  script_xref(name:"OSVDB", value:"54085");

  script_name(english:"Moodle Forum post.php Unauthorized Post Deletion CSRF");
  script_summary(english:"Looks for hidden sesskey variable in prune.html");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server contains a PHP application that is affected by a\n",
      "cross-site request forgery vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The 'forum' code in the version of Moodle installed on the remote host\n",
      "is affected by a cross-site request forgery vulnerability because it\n",
      "fails to properly validate requests before deleting forum posts.  If\n",
      "an attacker can trick a Moodle user into clicking on a malicious link,\n",
      "he may be able to leverage this issue to delete the user's posts.\n",
      "\n",
      "Note that this install is also likely affected by several other\n",
      "issues, including one allowing for arbitrary code execution,\n",
      "although Nessus has not checked for them."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://cvs.moodle.org/moodle/mod/forum/prune.html?r1=1.8&r2=1.8.4.1"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://docs.moodle.org/en/Moodle_1.9.4_release_notes"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://docs.moodle.org/en/Moodle_1.8.8_release_notes"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://moodle.org/mod/forum/discuss.php?d=115529"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Moodle version 1.9.4 / 1.8.8 / 1.7.7 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("moodle_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/moodle"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Grab prune.html.
  url = string(dir, "/mod/forum/prune.html");

  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(0);

  # There's a problem if it doesn't have the sesskey variable.
  if (
    '<form id="pruneform" method="get"' >< res[2] &&
    '<input type="hidden" name="confirm"' >< res[2] &&
    '<input type="hidden" name="sesskey"' >!< res[2]
  )
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
