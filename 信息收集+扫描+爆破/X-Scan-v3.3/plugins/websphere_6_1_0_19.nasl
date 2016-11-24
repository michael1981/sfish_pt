#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(34219);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2008-4111", "CVE-2009-0432", "CVE-2009-0433");
  script_bugtraq_id(31186, 33700);
  script_xref(name:"Secunia", value:"31892");

  script_name(english:"IBM WebSphere Application Server 6.1 < Fix Pack 19 Multiple Flaws");
  script_summary(english:"Reads the version number from the SOAP port");

 script_set_attribute(attribute:"synopsis", value:
"The remote application server is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"IBM WebSphere Application Server 6.1 before Fix Pack 19 appears to be
running on the remote host.  Such versions are reportedly affected by
multiple flaws :

  - An as-yet unspecified security exposure vulnerability 
    exists when the 'FileServing' feature in the Servlet 
    Engine / Web Container component is enabled. (PK64302). 

  - It may be possible for an attacker to obtain sensitive
    information from the file transfer servlet which is not
    secured by default. (PK59108)

 - A vulnerability in Web server plug-in could be exploited
   to trigger a denial of service attack. (PK63499)" );
 script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27007951#61019" );
 script_set_attribute(attribute:"solution", value:
"Apply Fix Pack 19 (6.1.0.19) or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
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
if (!banner || "Server: WebSphere Application Server/6.1" >!< banner) exit(0);


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

  if (ver[0] == 6 && ver[1] == 1 && ver[2] == 0 && ver[3] < 19)
  {
    if (report_verbosity)
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

