#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35659);
  script_version("$Revision: 1.1 $");

  script_cve_id("CVE-2009-0434");
  script_bugtraq_id(33700);

  script_name(english:"IBM WebSphere Application Server 6.1 < Fix Pack 21 Multiple Flaws");
  script_summary(english:"Reads the version number from the SOAP port");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote application server is affected by multiple vulnerabilities.\n"
    )
  );
  
  script_set_attribute(
    attribute:"description", 
    value:string(
      "IBM WebSphere Application Server 6.1 before Fix Pack 21 appears to be\n",
      "running on the remote host.  Such versions are reportedly affected by\n",
      "multiple flaws :\n\n",
      "  - Provided Performance Monitoring Infrastructure (PMI) is\n",
      "    enabled, it may be possible for a local attacker to\n",
      "    obtain sensitive information through 'Systemout.log' and\n",
      "    'ffdc' files which are written by PerfServlet.\n\n",
      "  - SSL Configuration settings attribute 'Security Level' \n",
      "    does not correctly enforce the level of encryption used\n",
      "    by the application server. (PK63182)\n")
  );

  script_set_attribute(
    attribute:"see_also", 
    value:"http://www-01.ibm.com/support/docview.wss?&uid=swg1PK63182"
  );

  script_set_attribute(
    attribute:"see_also", 
    value:"http://www-01.ibm.com/support/docview.wss?uid=swg27007951#61021"
  );

  script_set_attribute(
    attribute:"solution", 
    value:string("Apply Fix Pack 21 (6.1.0.21) or later.")
  );

  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N" 
  );
  
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

  if (ver[0] == 6 && ver[1] == 1 && ver[2] == 0 && ver[3] < 21)
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

