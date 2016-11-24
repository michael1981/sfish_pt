#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42348);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(36035);

  script_name(english:"ViewVC Invalid Parameter HTML Injection Vulnerability");
  script_summary(english:"Tries a non-persistent injection attack");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "An application running on the remote web server has an HTML injection\n",
      "vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The version of ViewVC running on the remote host is vulnerable to a\n",
      "HTML injection attack.  Requesting a URL with an invalid parameter\n",
      "name in the query string generates an error message that echoes back\n",
      "the parameter name.  Any URLs included in the invalid parameter name\n",
      "become hyperlinks.  A remote attacker could trick a user into\n",
      "requesting a malicious URL to facilitate a social engineering attempt.\n",
      "\n",
      "There is also reportedly an unrelated cross-site scripting issue in\n",
      "this version of ViewVC, though Nessus has not checked for that."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?846e7b9b"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?66b6cc34"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to ViewVC 1.0.9 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N"
  );
  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/03");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("viewvc_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");


port = get_http_port(default:80);
install = get_install_from_kb(appname:'viewvc', port:port);
if (isnull(install)) exit(1, "ViewVC wasn't detected on port " + port);

# Create/encode the injection attack
params = string(
  SCRIPT_NAME,
  '") was passed as a parameter. Visit http://www.example.com/ ',
  'to figure out why ("', SCRIPT_NAME, '=', unixtime()
);

# Shouldn't encode : / or =
unreserved = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.!~*'()-]:/=";
encoded_params = urlencode(str:params, unreserved:unreserved);

expected_output = string(
  'Visit <a href="http://www.example.com/">http://www.example.com/</a> ',
  'to figure out why ("', SCRIPT_NAME, '") was passed.'
);


# Make the GET request and see if injection worked
url = string(install['dir'], '/?', encoded_params);
res = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

if (expected_output >< res[2])
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report = get_vuln_report(items:url, port:port);
    security_warning(port:port, extra:report);
  }
  else security_warning(port);

  exit(0);
}
else exit(0, "The ViewVC install at "+build_url(port:port, qs:install['dir']+"/")+" is not affected.");
