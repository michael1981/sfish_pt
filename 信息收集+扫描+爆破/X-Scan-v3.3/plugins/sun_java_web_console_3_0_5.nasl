#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(31423);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2008-1286");
  script_bugtraq_id(28155);
  script_xref(name:"OSVDB", value:"42703");
  script_xref(name:"Secunia", value:"29290");

  script_name(english:"Sun Java Web Console < 3.0.5 Remote File Enumeration");
  script_summary(english:"Retrieves version info");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"According to its version, the installation of Sun Java Web Console on
the remote host may allow a local or remote unprivileged user to
determine the existence of files or directories in access restricted
directories, which could result in a loss of confidentiality." );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-26-231526-1" );
 script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch as discussed in the vendor advisory above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/www", 6788, 6789);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


# Only Linux and Solaris are affected according to Sun.
os = get_kb_item("Host/OS");
if (!os || ("Linux" >!< os && "Solaris" >!< os)) exit(0);


port = get_http_port(default:6788);
if (!get_port_state(port)) exit(0);


# Make sure it's Sun Java Web Console.
banner = get_http_banner(port:port);
if (!banner) exit(0);

redirect = strstr(banner, "Location:");
if (strlen(redirect)) redirect = redirect - strstr(redirect, '\r\n');
if (strlen(redirect) == 0 || "login/BeginLogin.jsp" >!< redirect) exit(0);


# Try to retrieve the version number.
req = http_get(item:"/console/html/en/console_version.shtml", port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);

if (
  "title>Sun Java(TM) Web Console: Version<" >< res &&
  '"VrsHdrTxt">Version ' >< res
)
{
  version = strstr(res, '"VrsHdrTxt">Version ') - '"VrsHdrTxt">Version ';
  if (strlen(version)) version = version - strstr(version, '</div');

  # nb: Sun only talks about 3.0.2, 3.0.3, and 3.0.4 as affected.
  if (strlen(version) && version =~ "^3\.0\.[2-4]($|[^0-9])")
  {
    if (report_verbosity)
    {
      report = string(
        "\n",
        "Sun Java Web Console version ", version, " is installed on the remote host.\n"
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
  }
}

