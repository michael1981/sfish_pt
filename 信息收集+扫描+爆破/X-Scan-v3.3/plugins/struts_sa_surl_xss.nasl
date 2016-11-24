#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(38208);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2008-6682");
  script_bugtraq_id(34686);
  script_xref(name:"Secunia", value:"32497");
  script_xref(name:"OSVDB", value:"54122");

  script_name(english:"Apache Struts s:a / s:url Tag href Element XSS");
  script_summary(english:"Attempts a non-persistent XSS attack");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote host is running a web application with multiple cross-site\n",
      "scripting vulnerabilities."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The web application on the remote host is vulnerable to cross-site\n",
      "scripting attacks. This is likely due to a vulnerable version of\n",
      "Apache Struts that fails to properly encode the parameters in the\n",
      "'s:a' and 's:url' tags.\n\n",
      "A remote attacker could exploit this by tricking a user into\n",
      "requesting a page with arbitrary script code injected. This could\n",
      "have consequences such as stolen authentication credentials."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://issues.apache.org/struts/browse/WW-2414"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://issues.apache.org/struts/browse/WW-2427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ed70fe34"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Struts version 2.1.1 / 2.0.11.1 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N"
  );
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("webmirror.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80, 8080);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


xss_params = '"><script>alert(\'' + SCRIPT_NAME + '\')</script>';

# Escapes parens so they're interpreted as literals in a regex
escaped_params = str_replace(string:xss_params, find:"(", replace:"\(");
escaped_params = str_replace(string:escaped_params, find:")", replace:"\)");
  
function attempt_xss(page)
{
  local_var url, res, report;

  url = string(page, "?", xss_params);
  res = http_send_recv3(
    method:"GET",
    item:url,
    port:port
  );
  
  if (isnull(res)) exit(0);
  
  if (egrep(string:res[2], pattern:'<a href="[^"]+' + escaped_params))
  {
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);

    if (report_verbosity > 0)
    {
      report = string(
        "Nessus was able to exploit the issue by using the following URL :\n\n",
        "  ", build_url(port:port, qs:page + '?'), xss_params, "\n\n",
        "Note that this particular URL will not trigger a JavaScript alert\n",
        "in all browsers.\n"
      ); 
      security_warning(port:port, extra:report);
    }
    else security_warning(port);

    exit(0);
  }
}

#
# Script execution begins here
#

if (thorough_tests)
{
  dirs = get_kb_list('www/' + port + '/content/directories');
  if (isnull(dirs)) dirs = make_list(cgi_dirs());
}
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
  attempt_xss(page:dir + '/');

if (thorough_tests)
{
  pages = get_kb_list(string("www/", port, "/content/extensions/jsp"));
  if (isnull(pages))
  {
    foreach page (pages)
      attempt_xss(page:page);
  }
}
