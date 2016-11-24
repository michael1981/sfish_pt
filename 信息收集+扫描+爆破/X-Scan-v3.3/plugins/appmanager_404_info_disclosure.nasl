#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(30056);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2008-0475");
  script_bugtraq_id(27443);
  script_xref(name:"OSVDB", value:"42043");

  script_name(english:"ManageEngine Applications Manager Invalid URI Remote Information Disclosure");
  script_summary(english:"Sends an invalid URL to AppManager");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application affected by an
information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running ManageEngine Applications Manager, a
web-based tool for monitoring websites, databases, and other
applications. 

The version of Applications Manager installed on the remote host
returns a summary of monitor groups and alerts in response to a
request with an invalid URL, which may reveal sensitive information
about the applications and services being monitored. 

Note that this version may also be affected by several other
information disclosure and cross-site scripting vulnerabilities,
although Nessus did not explicitly check for them." );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/advisories/28332/" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 9090);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:9090);

# Exploit the issue.
r = http_send_recv3(method:"GET", item:"/-", port:port, fetch404: TRUE);
if (isnull(r)) exit(0);
res = strcat(r[0], r[1], '\r\n', r[2]);

# There's a problem if we get to AppManager's Monitor Groups display.
if (
  "title>Applications Manager - Monitor Groups<" >< res &&
  "<!--$Id: Recent" >< res
) {
 security_warning(port);
 set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}

