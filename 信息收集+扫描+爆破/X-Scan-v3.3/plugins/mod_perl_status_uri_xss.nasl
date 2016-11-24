#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(36101);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2009-0796");
  script_bugtraq_id(34383);
  script_xref(name:"OSVDB", value:"53289");

  script_name(english:"mod_perl Apache::Status URI XSS");
  script_summary(english:"Tries to inject script code via URI");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server uses a module that is affected by a cross-site\n",
      "scripting vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote web server contains an embedded Perl interpreter along with\n",
      "a version of Apache2::Status / Apache::Status that fails to sanitize\n",
      "the request URL before using it to generate dynamic HTML output.  An\n",
      "attacker may be able to leverage this to inject arbitrary HTML and\n",
      "script code into a user's browser to be executed within the security\n",
      "context of the affected site."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://archives.neohapsis.com/archives/bugtraq/2009-04/0146.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://svn.apache.org/viewvc?view=rev&revision=761081"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://svn.apache.org/viewvc?view=rev&revision=760926"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.nessus.org/u?52e3d0cc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Upgrade to Apache2::Status revision 760926 / Apache::Status revision\n",
      "761081 or later."
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/apache");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# Unless we're being paranoid, make sure the banner looks like Apache.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (!banner) exit(0);
  if (!egrep(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/", string:banner)) exit(0);
}


exploit = string('nessus">', "<script>alert('", SCRIPT_NAME, "')</script>");


# Loop through directories.
dirs = list_uniq(make_list("/perl-status", cgi_dirs()));
if (thorough_tests) dirs = list_uniq(dirs, "/status");

foreach dir (dirs)
{
  url = string(dir, "/", exploit);
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(0);

  if (
    "Embedded Perl version <b>" >< res[2] &&
    string(url, '?env">Environment') >< res[2]
  )
  {
    set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

    if (report_verbosity > 0)
    {
      report = string(
        "\n",
        "Nessus was able to exploit the issue using the following URL :\n",
        "\n",
        "  ", build_url(port:port, qs:url), "\n"
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
  }
}
