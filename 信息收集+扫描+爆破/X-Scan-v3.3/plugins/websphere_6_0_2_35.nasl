#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38978);
  script_version("$Revision: 1.4 $");

  script_cve_id(
    "CVE-2009-1898", 
    "CVE-2009-1899", 
    "CVE-2009-1900", 
    "CVE-2009-1901"
  );
  script_bugtraq_id(35405);
  script_xref(name:"Secunia", value:"35301");

  script_name(english:"IBM WebSphere Application Server < 6.0.2.35 Multiple Vulnerabilities");
  script_summary(english:"Reads the version number from the SOAP port");

  script_set_attribute(attribute:"synopsis", value:
"The remote application server is affected by multiple vulnerabilities." );
  script_set_attribute(attribute:"description", value:
"IBM WebSphere Application Server 6.0.2 before Fix Pack 35 appears to
be running on the remote host.  Such versions are reportedly affected
by multiple vulnerabilities :

  - Non-standard HTTP methods are allowed. (PK73246)

  - Cross-site scripting vulnerabilities exist in sample
    applications. (PK76720)

  - If the admin console is directly accessed from http, 
    the console fails to redirect the connection to a 
    secure login page. (PK77010)

  - 'wsadmin' is affected by a security exposure. 
    (PK77495)

  - XML digital signature is affected by a security issue.
    (PK80596) 

  - In certain cases, application source files are exposed. 
    (PK81387)

  - Configservice APIs could display sensitive information. 
    (PK84999)" );

  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?rs=180&uid=swg27006876#60235" );
  script_set_attribute(attribute:"solution", value:
"Apply Fix Pack 35 (6.0.2.35) or later." );
  script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8880);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8880, embedded: 0);


# Make sure it's WebSphere.
banner = get_http_banner(port:port);
if (!banner || "Server: WebSphere Application Server/6.0" >!< banner) exit(0);

# Extract WebSphere Application Server's version from the banner.
res = http_get_cache(port:port, item:"/");
if (isnull(res)) exit(0);

if (':WASRemoteRuntimeVersion="' >< res)
{
  version = strstr(res, ':WASRemoteRuntimeVersion="') - ':WASRemoteRuntimeVersion="';
  if (strlen(version)) version = version - strstr(version, '"');
 
  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  if (ver[0] == 6 && ver[1] == 0 && ver[2] == 2 && ver[3] < 35)
  {
    if (report_verbosity > 0)
    {
      report = string(
        "\n",
        "WebSphere Application Server ", version, " is running on the remote host.\n"
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
  }
}
