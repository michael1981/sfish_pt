#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42338);
  script_version("$Revision: 1.1 $");

  script_cve_id("CVE-2009-3441");
  script_bugtraq_id(36504);
  script_xref(name:"OSVDB", value:"58374");
  script_xref(name:"Secunia", value:"36867");

  script_name(english:"OSSIM 'host/draw_tree.php' Access Restriction Weakness Information Disclosure");
  script_summary(english:"Tries to access a page that should require authentication");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "An application running on the remote web server has an unauthorized\n",
      "access vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The version of OSSIM running on the remote host has an unauthorized\n",
      "access vulnerability.  It is possible to access the\n",
      "'host/draw_tree.php' page without providing authentication.  This\n",
      "page includes information about the network's topology.  A remote\n",
      "attacker could use this information to mount further attacks."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/506663"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.alienvault.com/community.php?section=News#92"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to OSSIM version 2.1.2 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
  );
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/09/21"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/09/21"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/11/02"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("ossim_web_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80);

install = get_install_from_kb(appname:'ossim', port:port);
if (isnull(install)) exit(1, "OSSIM wasn't detected on port "+port+".");

url = string(install['dir'], '/host/draw_tree.php');
res = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

hdrs = parse_http_headers(status_line:res[0], headers:res[1]);
if (isnull(hdrs['$code'])) code = 0;
else code = hdrs['$code'];

if (code == 200 && 'pixmaps/theme/host.png' >< res[2])
{
  if (report_verbosity > 0)
  {
    report = get_vuln_report(
      header:"Nessus was able verify the issue using the following URL",
      items:url,
      port:port
    );

    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else exit(0, "The OSSIM install at "+build_url(port:port, qs:url)+" is not affected.");
