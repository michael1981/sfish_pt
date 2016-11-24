#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(35628);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2009-0496", "CVE-2009-0497");
  script_bugtraq_id(32945, 32944, 32943, 32940, 32939, 32938, 32937, 32935);
  script_xref(name:"OSVDB", value:"51419");
  script_xref(name:"OSVDB", value:"51420");
  script_xref(name:"OSVDB", value:"51421");
  script_xref(name:"OSVDB", value:"51422");
  script_xref(name:"OSVDB", value:"51423");
  script_xref(name:"OSVDB", value:"51424");
  script_xref(name:"OSVDB", value:"51425");
  script_xref(name:"OSVDB", value:"51426");
  script_xref(name:"Secunia", value:"33452");

  script_name(english:"Openfire < 3.6.3 Multiple Vulnerabilities");
  script_summary(english:"Checks version in admin login page");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by multiple
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Openfire / Wildfire, an instant messaging
server supporting the XMPP protocol. 

According to its version, the installation of Openfire or Wildfire is
affected by multiple vulnerabilities :

  - Multiple .jsp scripts namely, 'logviewer.jsp' 
    (BID 32935), 'group-summary.jsp' (BID 32937), 
    'user-properties.jsp' (BID 32938), 'audit-policy.jsp' 
    (BID 32939) and 'log.jsp' (BID 32940) fail to sanitize 
    input supplied by authorized users, and hence are 
    affected by cross-site scripting vulnerabilities.

  - Provided an administrator's browser session is allowed 
    to execute arbitrary Javascript and an attacker has 
    managed to steal session cookies, it may be possible 
    for an attacker to execute arbitrary code on the remote 
    system by uploading a new server plugin.

  - Pages 'security-audit-viewer.jsp', 'server-properties.js' 
    (BID 32943) and 'muc-room-summary.jsp' (BID 32944) are 
    affected by a stored cross-site scripting 
    vulnerabilities. (BID 32943)

  - log.jsp fails to sanitize input passed to the 'log' 
    parameter by an authorized user, and hence it may be 
    possible for an authenticated attacker to read arbitrary 
    .log files. (BID 32945)" );
 script_set_attribute(attribute:"see_also", value:"http://www.coresecurity.com/content/openfire-multiple-vulnerabilities" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2009-01/0047.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Openfire version 3.6.3 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );

script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 9090);

  exit(0);
}


include("global_settings.inc");
include("http.inc");
include("misc_func.inc");

# nb: banner checks of open-source software are prone to false-
#     positives so only run the check if reporting is paranoid.
if (report_paranoia < 2) exit(0);

port = get_http_port(default:9090);
if (!get_port_state(port)) exit(0);

# Grab the version from the admin console's login page.
res = http_send_recv3(method:"GET", item: "/login.jsp?url=%2Findex.jsp",port:port);
if (res == NULL) exit(0);

if (
  'id="jive-loginVersion">' >< res[2] &&
  (
    "<title>Openfire Admin Console" >< res[2] &&
    "Openfire, Version: " >< res[2]
  ) ||
  (
    "<title>Wildfire Admin Console" >< res[2] &&
    "Wildfire, Version: " >< res[2]
  )
)
{
  prod = strstr(res[2], "<title>") - "<title>";
  prod = prod - strstr(prod, " Admin Console</title>");

  ver = strstr(res[2], "fire, Version: ") - "fire, Version: ";
  if (ver) ver = ver - strstr(ver, '\n');

  # The issue was addressed in version 3.6.3 so treat any 
  # versions before that as vulnerable.
  if (
    strlen(ver) && ver =~ "^([0-2]\.|3\.([0-5][^0-9]|6\.[0-2][a]*$))" &&
    prod =~ "^(Open|Wild)fire$"
  )
  {
    if (report_verbosity)
    {
      report = string(
        "\n",
        prod, " version ", ver, " is installed on the remote host.\n"
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
  }
}
