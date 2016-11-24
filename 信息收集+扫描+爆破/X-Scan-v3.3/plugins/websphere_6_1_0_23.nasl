#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(36161);
  script_version("$Revision: 1.4 $");

  script_cve_id(
    "CVE-2008-4284", 
    "CVE-2009-0508", 
    "CVE-2009-0855", 
    "CVE-2009-0856", 
    "CVE-2009-0891", 
    "CVE-2009-0892", 
    "CVE-2009-1172"
  );
  script_bugtraq_id(34330, 34501, 34502, 35610);
  script_xref(name:"Secunia", value:"33729");
  script_xref(name:"Secunia", value:"34131");
  script_xref(name:"Secunia", value:"34283");
  script_xref(name:"OSVDB", value:"52402");
  script_xref(name:"OSVDB", value:"52596");
  script_xref(name:"OSVDB", value:"52620");
  script_xref(name:"OSVDB", value:"52829");
  script_xref(name:"OSVDB", value:"53251");
  script_xref(name:"OSVDB", value:"53268");

  script_name(english:"IBM WebSphere Application Server < 6.1.0.23 Multiple Flaws");
  script_summary(english:"Reads the version number from the SOAP port");

  script_set_attribute(attribute:"synopsis", value:
"The remote application server is affected by multiple vulnerabilities." );
  script_set_attribute(attribute:"description", value:
"IBM WebSphere Application Server 6.1 before Fix Pack 23 appears to
be running on the remote host.  Such versions are reportedly affected
by multiple vulnerabilities :

  - Provided an attacker has valid credentials, it may be
    possible to hijack an authenticated session. (PK66676)

  - It may be possible for a remote attacker to redirect
    users to arbitrary sites using ibm_security_logout 
    servlet. (PK71126) 

  - Under certain conditions it may be possible to access
    administrative console user sessions. (PK74966)

  - If APAR PK41002 has been applied, a vulnerability in
    the JAX-RPC WS-Security component could incorrectly
    validate 'UsernameToken'. (PK75992)

  - Sample applications shipped with IBM WebSphere
    Application Server are affected by cross-site scripting
    vulnerabilities. (PK76720)

  - The adminitrative console is affected by a cross-site
    scripting vulnerability. (PK77505)

  - It may be possible for an attacker to read arbitrary
    application-specific war files. (PK81387)");

  script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg1PK71126" );
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21367223" );
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?rs=180&uid=swg27007951#61023" );
  script_set_attribute(attribute:"solution", value:
"Apply Fix Pack 23 (6.1.0.23) or later." );
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

port = get_http_port(default:8880);

# Make sure it's WebSphere.
banner = get_http_banner(port:port);
if (!banner || "Server: WebSphere Application Server/6.1" >!< banner) exit(0);

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

  if (ver[0] == 6 && ver[1] == 1 && ver[2] == 0 && ver[3] < 23)
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
