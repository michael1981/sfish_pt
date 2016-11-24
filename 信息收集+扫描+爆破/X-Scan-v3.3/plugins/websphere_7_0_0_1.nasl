#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(35082);
  script_version("$Revision: 1.7 $");

  script_cve_id(
    "CVE-2009-0504",	
    "CVE-2008-5411",
    "CVE-2008-5412",
    "CVE-2008-5413",
    "CVE-2008-5414",
    "CVE-2009-0434",
    "CVE-2009-0438"
  );
  script_bugtraq_id(32679, 33700, 33879);
  script_xref(name:"Secunia", value:"33022");

  script_name(english:"IBM WebSphere Application Server 7.0 < Fix Pack 1");
  script_summary(english:"Reads the version number from the SOAP port");

 script_set_attribute(attribute:"synopsis", value:
"The remote application server is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"IBM WebSphere Application Server 7.0 before Fix Pack 1 appears to be
running on the remote host.  Such versions are reportedly affected by
multiple vulnerabilities. 

  - The PerfServlet code writes sensitive information in
    the 'systemout.log' and ffdc files, provided 
    Performance Monitoring Infrastructure (PMI) is enabled. 
    (PK63886)
 
  - A vulnerability in feature pack for web services could
    lead to information disclosure due to 'userNameToken'.
    (PK67282)
 
  - A user locked by the underlying OS may be able to 
    authenticate via the administrative console. (PK67909)

  - Web authentication options 'Authenticate when any URI is
    accessed' and 'Use available authentication data when an
    unprotected URI is accessed' are ignored. Servlets with
    with no security constraints are not authenticated and
    usernames with '@' symbol fail to authenticate.
    (PK71826)

  - WS-Security in JAX-WS does not remove UsernameTokens
    from client cache on failed logins. (PK72435)

  - WSPolicy discloses password in SOAP messages even though
    IDAssertion.isUsed is set to true, and a simple user
    name token policyset is used. (PK73573)

  - SSL traffic is routed over unencrypted TCP routes.
    (PK74777)

  - By sending a specially crafted request, it may be
    possible for an remote attacker to gain access to
    certain JSP pages that require authorization.
    (PK75248)" );
 script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24021073" );
 script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1PK67909" );
 script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1PK71826" );
 script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1PK72435" );
 script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27014463#7001" );
 script_set_attribute(attribute:"solution", value:
"Apply Fix Pack 1 (7.0.0.1) or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8880);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:8880);
if (!get_port_state(port)) exit(0);


# Extract WebSphere Application Server's version from the banner.
banner = get_http_banner(port:port);
if (!banner || "Server: WebSphere Application Server/7.0" >!< banner) exit(0);

res = http_get_cache(port:port, item:"/"); 
if (res == NULL) exit(0);

if (':WASRemoteRuntimeVersion="' >< res)
{
  version = strstr(res, ':WASRemoteRuntimeVersion="') - ':WASRemoteRuntimeVersion="';
  if (strlen(version)) version = version - strstr(version, '"');

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  if (ver[0] == 7 && ver[1] == 0 && ver[2] == 0 && ver[3] < 1)
  {
    if (report_verbosity)
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
