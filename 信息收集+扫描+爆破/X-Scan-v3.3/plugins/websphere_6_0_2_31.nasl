#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(34501);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2008-4111", 
		"CVE-2008-4678", 
		"CVE-2008-4679", 
		"CVE-2009-0434");
  script_bugtraq_id(31839, 31186, 33700);
  script_xref(name:"OSVDB", value:"48143");
  script_xref(name:"OSVDB", value:"49782");
  script_xref(name:"OSVDB", value:"49784");
  script_xref(name:"Secunia", value:"32296");

  script_name(english:"IBM WebSphere Application Server < 6.0.2.31 Multiple Vulnerabilities");
  script_summary(english:"Reads the version number from the SOAP port");

 script_set_attribute(attribute:"synopsis", value:
"The remote application server is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"IBM WebSphere Application Server 6.0.2 before Fix Pack 31 appears to
be running on the remote host.  Such versions are reportedly affected
by multiple vulnerabilities. 
 
  - By sending a specially crafted HTTP request with the 
    'Host' header field set to more than 256 bytes, it may 
    be possible to crash the remote application server.
    (PK69371)
 
  - An unspecified security exposure vulnerability exists if
    'fileServing' feature is enabled. (PK64302)

  - Web services security fails to honor Certificate 
    Revocation Lists (CRL) configured in Certificate Store 
    Collections. (PK61258)

  - Provided Performance Monitoring Infrastructur (PMI) is 
    enabled, it may be possible for an local attacker to
    obtain sensitive information." );
 script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1PK69371" );
 script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1PK61258" );
 script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24020788" );
 script_set_attribute(attribute:"solution", value:
"Apply Fix Pack 31 (6.0.2.31) or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P" );

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


# Make sure it's WebSphere.
banner = get_http_banner(port:port);
if (!banner || "Server: WebSphere Application Server/6.0" >!< banner) exit(0);


# Extract WebSphere Application Server's version from the banner.
res = http_get_cache(port:port, item:"/");
if (res == NULL) exit(0);

if (':WASRemoteRuntimeVersion="' >< res)
{
  version = strstr(banner, ':WASRemoteRuntimeVersion="') - ':WASRemoteRuntimeVersion="';
  if (strlen(version)) version = version - strstr(version, '"');
 
  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  if (ver[0] == 6 && ver[1] == 0 && ver[2] == 2 && ver[3] < 31)
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
