#
# (C) Tenable Network Security, Inc.
#

# Thanks to OSVDB for the PoC.


include("compat.inc");


if (description)
{
  script_id(42352);
  script_version("$Revision: 1.1 $");

  script_cve_id("CVE-2009-1987");
  script_bugtraq_id(35691);
  script_xref(name:"OSVDB", value:"55909");

  script_name(english:"PeopleSoft PeopleTools JMS Listening Connector Activity Parameter XSS");
  script_summary(english:"Tries to inject script code into JMS Listening Connector Administrator interface");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts an application that is prone to a
cross-site scripting attack."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote web server is running an instance of PeopleSoft PeopleTools
that fails to sanitize user-supplied input to the 'Activity' parameter
upon submission to the JMS Listening Connector Administrator interface
before using it to generate dynamic HTML output.  An attacker may be
able to leverage this to inject arbitrary HTML and script code into a
user's browser to be executed within the security context of the
affected site."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.nessus.org/u?e1e87349"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to version 8.49.22 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N"
  );
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/07/27"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/07/14"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/10/29"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 3000);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:3000);


# Unless we're being paranoid, make sure the banner looks like PeopleSoft.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (banner && "X-Powered-By: Servlet/" >!< banner) exit(0, "Server response header suggests it's not PeopleSoft.");
}


# Try to exploit the issue.
alert = string("alert('", SCRIPT_NAME, "');");
test_cgi_xss(
  port     : port,
  cgi      : "/JMSListeningConnectorAdministrator",
  dirs     : make_list("/PSIGW"),
  qs       : "Activity="+urlencode(str:alert),
  pass_str : alert,
  pass2_re : "<H3>JMSListeningConnector"
);
