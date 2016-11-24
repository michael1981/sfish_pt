#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(41057);
  script_version("$Revision: 1.1 $");

  script_cve_id(
    "CVE-2009-0023",
    "CVE-2009-1955",
    "CVE-2009-2091",
    "CVE-2009-2742",
    "CVE-2009-2743",
    "CVE-2009-2744",
    "CVE-2009-3106"
  );
  script_bugtraq_id(36455, 36456, 36458);

  script_name(english:"IBM WebSphere Application Server < 6.1.0.27 Multiple Vulnerabilities");
  script_summary(english:"Reads the version number from the SOAP port");

  script_set_attribute(attribute:"synopsis", value:
"The remote application server is affected by multiple vulnerabilities." );
  script_set_attribute(attribute:"description", value:
"IBM WebSphere Application Server 6.1 before Fix Pack 27 appears to
be running on the remote host.  Such versions are reportedly affected
by multiple vulnerabilities :

  - The Eclipse help system included with WebSphere 
    Application Server is affected by a cross-site 
    scripting vulnerability. (PK78917)

  - It may be possible to bypass security restrictions
    using a specially crafted HTTP HEAD method. (PK83258)

  - New applications deployed in WebSphere Application
    Server for z/OS prior to 1.8 are saved on the file
    system with insecure privileges resulting in
    disclosure of sensitive information. (PK83308)

  - If JAAS-J2C Authentication Data is configured using
    wsadmin scripts, the password value may appear in
    FFDC logs. (PK86137)
    
  - Apache APR-util is affected by a denial of service 
    issue. (PK88341)

  - Due to an error in expat XML parser, APR-util is 
    affected by a denial of service issue. (PK88342)
 
  - It may be possible to trigger a denial of service
    attack due to errors in Fix Packs 6.1.0.23 and 
    6.1.0.25. (PK91709)");

  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?rs=180&uid=swg27007951#61027" );
  script_set_attribute(attribute:"solution", value:
"Apply Fix Pack 27 (6.1.0.27) or later." );
  script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
 
  script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/23");

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
if (!banner) exit(1, "get_http_banner() returned NULL for port "+port+".");
if ("Server: WebSphere Application Server/6.1" >!< banner) 
  exit(0, "The banner for port "+port+" is not from WebSphere Application Server 6.1.");

# Extract WebSphere Application Server's version from the banner.
res = http_get_cache(port:port, item:"/");
if (isnull(res)) exit(1, "The web server failed to respond.");

if (':WASRemoteRuntimeVersion="' >< res)
{
  version = strstr(res, ':WASRemoteRuntimeVersion="') - ':WASRemoteRuntimeVersion="';
  if (strlen(version)) version = version - strstr(version, '"');
 
  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  if (ver[0] == 6 && ver[1] == 1 && ver[2] == 0 && ver[3] < 27)
  {
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);

    if (report_verbosity > 0)
    {
      report = string(
        "\n",
        "WebSphere Application Server ", version, " is running on the remote host.\n"
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);

    exit(0);
  }
  else exit(0, "The host is not affected since WebSphere Application Server "+version+" is installed."); 
}
else exit(1, "Unexpected response received from the SOAP service on port "+port+".");
