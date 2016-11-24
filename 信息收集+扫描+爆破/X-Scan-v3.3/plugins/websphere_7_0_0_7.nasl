#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42821);
  script_version("$Revision: 1.1 $");

  script_cve_id("CVE-2009-2746", "CVE-2009-2747", "CVE-2009-3106");
  script_bugtraq_id(37015);
  script_xref(name:"OSVDB", value:"59961");
  script_xref(name:"Secunia", value:"37379");

  script_name(english:"IBM WebSphere Application Server 7.0 < Fix Pack 7");
  script_summary(english:"Reads the version number from the SOAP port");

  script_set_attribute(attribute:"synopsis", value:
"The remote application server is affected by multiple vulnerabilities." );
  script_set_attribute(attribute:"description", value:
"IBM WebSphere Application Server 7.0 before Fix Pack 7 appears to be
running on the remote host.  Such versions are reportedly affected by
multiple vulnerabilities.

  - A cross-site request forgery vulnerability exists due
    to insufficient validation of user supplied input by
    the administrative console. (PK87176)

  - Due to an error in Java Naming and Directory Interface,
    it may be possible to obtain sensitive information.
    (PK91414).

  - The administrative console is affected by a
    cross-site scripting vulnerability. (PK92057)

  - It may be possible to bypass security restrictions
    using a specially crafted HTTP HEAD method. 
    (PK83258)"
  );

  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?rs=180&uid=swg27014463#7007" );
 
  script_set_attribute(attribute:"solution", value:
"Apply Fix Pack 7 (7.0.0.7) or later." );
  script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N" );

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/13");
  script_set_attribute(attribute:"plugin_publication_date",value:"2009/11/13");
 
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
if (banner && "Server: WebSphere Application Server/7.0" >!< banner) 
 exit(1,"Remote banner not from WebSphere Application Server/7.0");

res = http_get_cache(port:port, item:"/"); 
if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

if (':WASRemoteRuntimeVersion="' >< res)
{
  version = strstr(res, ':WASRemoteRuntimeVersion="') - ':WASRemoteRuntimeVersion="';
  if (strlen(version)) version = version - strstr(version, '"');

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  if (ver[0] == 7 && ver[1] == 0 && ver[2] == 0 && ver[3] < 7)
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
    exit(0);
  }
  else exit(0,"WebSphere Application Server version "+version+" is installed and hence not vulnerable.");
}
else exit(1, "Can't extract version from response on port "+port+".");
