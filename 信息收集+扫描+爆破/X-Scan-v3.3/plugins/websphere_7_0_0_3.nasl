#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(36133);
  script_version("$Revision: 1.6 $");

  script_cve_id(
    "CVE-2009-0508",
    "CVE-2009-0892",
    "CVE-2009-0903",
    "CVE-2009-1172",
    "CVE-2009-1173",
    "CVE-2009-1174"
  );
  script_bugtraq_id(34104, 34330, 34358, 34506, 35594, 35610);
  script_xref(name:"OSVDB", value:"52620");
  script_xref(name:"OSVDB", value:"56161");
  script_xref(name:"Secunia", value:"34131");
  script_xref(name:"Secunia", value:"34461");

  script_name(english:"IBM WebSphere Application Server 7.0 < Fix Pack 3");
  script_summary(english:"Reads the version number from the SOAP port");

  script_set_attribute(attribute:"synopsis", value:
"The remote application server is affected by multiple vulnerabilities." );
  script_set_attribute(attribute:"description", value:
"IBM WebSphere Application Server 7.0 before Fix Pack 3 appears to be
running on the remote host.  Such versions are reportedly affected by
multiple vulnerabilities.

  - Under certain conditions it may be possible to access
    administrative console user sessions. (PK74966)

  - The adminitrative console is affected by a cross-site
    scripting vulnerability. (PK77505)

  - If APAR PK41002 has been applied, a vulnerability in the
    JAX-RPC WS-Security component could incorrectly 
    validate 'UsernameToken'. (PK75992)

  - Sample applications shipped with IBM WebSphere
    Application Server are affected by cross-site scripting
    vulnerabilities. (PK76720)

  - Certain files associated with interim fixes for Unix-
    based versions of IBM WebSphere Application Server are 
    built with insecure file permissions. (PK77590)

  - The Web Services Security component is affected by an
    unspecified security issue in digital-signature
    specification. (PK80596)

  - It may be possible for an attacker to read arbitrary
    application-specific war files. (PK81387)

  - A security bypass caused by inbound requests that lack
    a SOAPAction or WS-Addressing Action. (PK72138)" );
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24022693" );
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24022456" );
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21367223" );
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27014463#7003" );
  script_set_attribute(attribute:"solution", value:
"Apply Fix Pack 3 (7.0.0.3) or later." );
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

# Extract WebSphere Application Server's version from the banner.
banner = get_http_banner(port:port);
if (!banner || "Server: WebSphere Application Server/7.0" >!< banner) exit(0);

res = http_get_cache(port:port, item:"/"); 
if (isnull(res)) exit(0);

if (':WASRemoteRuntimeVersion="' >< res)
{
  version = strstr(res, ':WASRemoteRuntimeVersion="') - ':WASRemoteRuntimeVersion="';
  if (strlen(version)) version = version - strstr(version, '"');

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  if (ver[0] == 7 && ver[1] == 0 && ver[2] == 0 && ver[3] < 3)
  {
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);

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
