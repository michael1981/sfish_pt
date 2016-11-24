#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42340);
  script_version("$Revision: 1.1 $");

  script_cve_id("CVE-2009-1872", "CVE-2009-1875");
  script_bugtraq_id(36046, 36053);
  script_xref(name:"OSVDB", value:"57183");
  script_xref(name:"OSVDB", value:"57188");
  script_xref(name:"Secunia", value:"36329");

  script_name(english:"Adobe ColdFusion <= 8.0.1 Multiple XSS");
  script_summary(english:"Attempts a non-persistent XSS attack");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "An application running on the remote web server has multiple\n",
      "cross-site scripting vulnerabilities."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The version of ColdFusion running on the remote host is vulnerable to\n",
      "a cross-site scripting attack.  '_logintowizard.cfm' and 'index.cfm'\n",
      "do not sanitize the query string of the URL, which could result in\n",
      "the injection of HTML or script code.  A remote attacker could\n",
      "exploit this by tricking a user into requesting a malicious URL.\n\n",
      "This version of ColdFusion has other cross-site scripting\n",
      "vulnerabilities, though Nessus has not checked for those issues."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.dsecrg.com/pages/vul/show.php?id=122"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://archives.neohapsis.com/archives/bugtraq/2009-08/0130.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.adobe.com/support/security/bulletins/apsb09-12.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Apply the relevant hotfixes referenced in the vendor's advisory."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N"
  );
  script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/02");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("coldfusion_detect.nasl");
  script_require_ports("Services/www", 80, 8500);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80);
install = get_install_from_kb(appname:'coldfusion', port:port);
if (isnull(install)) exit(1, "ColdFusion wasn't detected on port "+port+".");

xss = string('>"><script>alert("', SCRIPT_NAME, '")</script>');

# Key - affected page
# Value - trailing context to detect successful injection
attempts = make_array(
  '/wizards/common/_logintowizard.cfm',
  '" method="POST" onsubmit="return _CF_checkloginform(this)">',
  '/administrator/index.cfm',
  '">'
);

# Try an XSS attack on each page
vuln_urls = make_list();

foreach page (keys(attempts))
{
  url = string(install['dir'], page, '?', xss);
  expected_output = string(url, attempts[page]);
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

  if (expected_output >< res[2]) vuln_urls = make_list(vuln_urls, url);

  # If this attack succeeded, only keep checking if thoro tests are enabled
  if (!thorough_tests && max_index(vuln_urls) > 0) break;
}

# Report on any XSS found
if (max_index(vuln_urls) > 0)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    if (max_index(vuln_urls) == 1)
      trailer = '\nNote that this proof-of-concept attack';
    else
      trailer = '\nNote that these proof-of-concept attacks';

    trailer += ' will not work with all browsers.\n';
    report = get_vuln_report(items:vuln_urls, trailer:trailer, port:port);

    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else exit(0, "The ColdFusion install at "+build_url(port:port, qs:install['dir'])+" is not affected.");
