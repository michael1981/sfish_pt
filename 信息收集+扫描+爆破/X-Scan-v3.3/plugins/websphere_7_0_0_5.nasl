#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40823);
  script_version("$Revision: 1.2 $");

  script_cve_id(
  "CVE-2009-0899", 
  "CVE-2009-1195", 
  "CVE-2009-1898",
  "CVE-2009-1899",
  "CVE-2009-1900",
  "CVE-2009-1901",
  "CVE-2009-2085",
  "CVE-2009-2087",
  "CVE-2009-2088",
  "CVE-2009-2089", 
  "CVE-2009-0899", 
  "CVE-2009-2090",
  "CVE-2009-2091",
  "CVE-2009-2092"
  );
  script_bugtraq_id(36153, 36154, 36155, 36156, 36157, 36158, 36163);
  script_xref(name:"OSVDB", value:"57036");
  script_xref(name:"OSVDB", value:"57037");
  script_xref(name:"OSVDB", value:"57038");
  script_xref(name:"OSVDB", value:"57040");
  script_xref(name:"OSVDB", value:"57041");
  script_xref(name:"OSVDB", value:"57044");
  script_xref(name:"OSVDB", value:"57045");

  script_name(english:"IBM WebSphere Application Server 7.0 < Fix Pack 5");
  script_summary(english:"Reads the version number from the SOAP port");

  script_set_attribute(attribute:"synopsis", value:
"The remote application server is affected by multiple vulnerabilities." );
  script_set_attribute(attribute:"description", value:
"IBM WebSphere Application Server 7.0 before Fix Pack 5 appears to be
running on the remote host.  Such versions are reportedly affected by
multiple vulnerabilities.

  - Non-standard HTTP methods are allowed. (PK73246)

  - If the admin console is directly accessed from HTTP,
    the console fails to redirect the connection to a
    secure login page. (PK77010)

  - An error in Single Sign-on (SSO) with SPNEGO 
    implementation could allow a remote attacker
    to bypass security restrictions. (PK77465)

  - 'wsadmin' is affected by a security exposure. 
    (PK77495)  

  - Security flag 'isSecurityEnabled' is incorrectly set
    after migrating from VMM. (PK78134)

  - Use of insecure password obfuscation algorithm by Web
    services could result in weaker than expected security
    provided the client module specifies a password in 
    ibm-webservicesclient-bind.xmi and target environment 
    has custom password encryption enabled. (PK79275)

  - After upgrading from WebSphere Application Server V6.1 
    to V7.0 with tracing enabled, an attacker may be able
    view sensitive information by viewing the trace files.
    (PK80337)  

  - If CSIv2 Security is configured with Identity 
    Assertion, it may be possible for a remote
    attacker to bypass security restrictions. (PK83097)

  - New applications deployed in WebSphere Application 
    Server for z/OS prior to 1.8 are saved on the file
    system with insecure privileges resulting in
    disclosure of sensitive information. (PK83308)

  - Configservice APIs could display sensitive information.
    (PK84999)

  - Vulnerabilities in Apache HTTP server could allow a
    local user to gain elevated privileges. (PK86232)

  - A error in 'wsadmin' could allow a remote attacker
    to bypass security restrictions. (PK86328)
   
  - A vulnerability in portlet serving enable parameter
    could allow an attacker to bypass security restriction
    and gain unauthorized access to the application. 
    (PK89385)");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27014463#7005" );
 
  script_set_attribute(attribute:"solution", value:
"Apply Fix Pack 5 (7.0.0.5) or later." );
  script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/31");
 
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

# Extract WebSphere Application Server's version from the banner.
banner = get_http_banner(port:port);
if (!banner || "Server: WebSphere Application Server/7.0" >!< banner) 
 exit(1,"Remote banner not from WebSphere Application Server/7.0");

res = http_get_cache(port:port, item:"/"); 
if (isnull(res)) exit(1,"NULL response for http_get_cache request.");

if (':WASRemoteRuntimeVersion="' >< res)
{
  version = strstr(res, ':WASRemoteRuntimeVersion="') - ':WASRemoteRuntimeVersion="';
  if (strlen(version)) version = version - strstr(version, '"');

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  if (ver[0] == 7 && ver[1] == 0 && ver[2] == 0 && ver[3] < 5)
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
  else
   exit(0,"Installed version of WebSphere Application Server is not vulnerable.");
}
