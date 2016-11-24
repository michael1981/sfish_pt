#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(41946);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2009-3068");
  script_bugtraq_id(36245);
  script_xref(name:"Secunia", value:"36467");
  script_xref(name:"OSVDB", value:"57896");

  script_name(english:"Adobe RoboHelp Server Security Bypass (APSA09-05)");
  script_summary(english:"Looks at the HTTP status code of a bad request");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "A web application running on the remote host has a security bypass\n",
      "vulnerability that can lead to arbitrary command execution."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The version of RoboHelp Server running on the remote host has a\n",
      "security bypass vulnerability.  Arbitrary files can be uploaded to\n",
      "the web server by using a specially crafted POST request.  Uploading\n",
      "a JSP file can result in command execution as SYSTEM.\n\n",
      "Since safe checks are enabled, Nessus detected this vulnerability\n",
      "solely by issuing an incomplete POST request and checking the\n",
      "resulting HTTP status code."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.intevydis.com/blog/?p=69"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.zerodayinitiative.com/advisories/ZDI-09-066/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://archives.neohapsis.com/archives/fulldisclosure/2009-09/0410.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.adobe.com/support/security/advisories/apsa09-05.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.adobe.com/support/security/bulletins/apsb09-14.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Apply the patch referenced in Adobe's advisory."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/09/09"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/09/18"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/09/30"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80, 8080);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:8080);
  
# Make sure the web page exists before making a POST request
page = '/robohelp/server?';
query = 'area=' + SCRIPT_NAME;
url = page + query;
res = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

# If we're not redirected to a project or a welcome screen, this probably isn't
# Adobe RoboHelp. If any projects have been published, we should see our query
# string in the redirect.  If no projects have been published, we should see a
# redirect to a welcome page
pattern = string(
  'http-equiv="refresh" content="0;url=(',
  'http://[^/]+',
  ereg_replace(string:page, pattern:"\?", replace:"\?"), urlencode(str:query),
  '|',
  '/robohelp/robo//server/resource/mr_sys_welcome.htm)'
);
if (!egrep(pattern:pattern, string:tolower(res[2])) )
  exit(1, "RoboHelp doesn't appear to be available via port "+port+".");

# Since we're not providing any POST data, a file won't be created, but we'll
# be able to tell if the system is patched based on the HTTP return code
url = '/robohelp/server?PUBLISH=1';
headers = make_array("UID", rand());
res = http_send_recv3(
  method:"POST",
  item:url,
  port:port,
  add_headers:headers
);
if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

headers = parse_http_headers(status_line:res[0], headers:res[1]);
http_code = headers['$code'];
if (isnull(http_code)) exit(1, "Error parsing HTTP response code");

# If we get an HTTP OK, it's vulnerable.  If our request required authentication# it's patched
if (http_code == 200) security_hole(port);
else if (http_code == 401) exit(0, "The host is not affected");
else exit(1, "Unexpected HTTP status code");
