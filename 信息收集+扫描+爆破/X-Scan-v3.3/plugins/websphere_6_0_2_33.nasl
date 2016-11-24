#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(36132);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2009-0891", "CVE-2009-0506");
  script_bugtraq_id(33884, 34330, 35610);
  script_xref(name:"OSVDB", value:"52608");
  script_xref(name:"Secunia", value:"34038");

  script_name(english:"IBM WebSphere Application Server < 6.0.2.33 Multiple Vulnerabilities");
  script_summary(english:"Reads the version number from the SOAP port");

  script_set_attribute(attribute:"synopsis", value:
"The remote application server is affected by multiple vulnerabilities." );
  script_set_attribute(attribute:"description", value:
"IBM WebSphere Application Server 6.0.2 before Fix Pack 33 appears to
be running on the remote host.  Such versions are reportedly affected
by multiple vulnerabilities :

  - Provided an attacker has valid credentials, it may be
    possible to hijack an authenticated session. (PK66676)

  - The PerfServlet code writes sensitive information in
    the 'systemout.log' and ffdc files, provided
    Performance Monitoring Infrastructure (PMI) is enabled.
    (PK63886)

  - It may be possible to login to the administrative
    console using a user account that is locked by the
    operating system. (PK67909)

  - An unknown vulnerability affects z/OS-based IBM 
    WebSphere application servers. (PK71143)

  - An unspecified vulnerability in the administrative 
    console could allow arbitrary file retrieval from the
    remote system. (PK72036)

  - If APAR PK41002 has been applied, a vulnerability in 
    the JAX-RPC WS-Security component could incorrectly 
    validate 'UsernameToken'. (PK75992)

  - Certain files associated with interim fixes for Unix-
    based versions of IBM WebSphere Application Server are 
    built with insecure file permissions. (PK78960)" );
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27006876#60233" );
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1PK67909" );
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21367223" );
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24022693" );
  script_set_attribute(attribute:"solution", value:
"Apply Fix Pack 33 (6.0.2.33) or later." );
  script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
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

  if (ver[0] == 6 && ver[1] == 0 && ver[2] == 2 && ver[3] < 33)
  {
    if (report_verbosity > 0)
    {
      report = string(
        "\n",
        "WebSphere Application Server ", version, " is running on the remote host.\n"
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
  }
}
