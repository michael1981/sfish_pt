#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(38832);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2008-5077", "CVE-2008-5814", "CVE-2009-1418");
  script_bugtraq_id(35031);
  script_xref(name:"OSVDB", value:"54608");
  script_xref(name:"Secunia", value:"35108");

  script_name(english:"HP System Management Homepage < 3.0.1.73 Multiple Flaws");
  script_summary(english:"Checks version of HP SMH");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote web server is affected by multiple vulnerabilities.");

  script_set_attribute(
    attribute:"description", 
    value:
"The remote host appears to be running HP System Management Homepage
(SMH), a web-based management interface for ProLiant and Integrity
servers. The version of HP SMH installed on the remote host is 
affected by multiple flaws :

  - A weakness in PHP could be exploited to perform cross-
    site scripting attacks, provided PHP directive 'display 
    errors' is enabled. (CVE-2008-5814) 

  - Vulnerability in OpenSSL versions less than 0.9.8i
    could be exploited to bypass the validation of the 
    certificate chain. (CVE-2008-5077)

  - Windows and Linux versions of SMH are affected by a
    cross-site scripting vulnerability. (CVE-2009-1418)" );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01743291" );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01745065" );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to HP System Management Homepage v3.0.1.73 or later." );
  script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/www", 2301, 2381);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

# nb: HP only says Linux and Windows are affected

os = get_kb_item("Host/OS");
if (!os || ("Windows" >!< os && "Linux" >!< os)) exit(0);

port = get_http_port(default:2301,embedded:TRUE);

# Grab the version from the Server response header.
banner = get_http_banner(port:port);
if (!banner) exit(0);

server = strstr(banner, "Server: ");
server = server - strstr(server, '\r\n');

if ("System Management Homepage/" >< server)
{
  version = strstr(server, "System Management Homepage/") - "System Management Homepage/";
  # Get rid of rest of the banner. 
  # for e.g 3.0.1.73 httpd/2.2.6+
  version = ereg_replace(pattern:"^([0-9.]+).*",string:version,replace:"\1");
 
  ver = split(version, sep:'.', keep:FALSE);
  
  if ((ver[0]  < 3) ||
      (ver[0] == 3 && ver[1] == 0 && ver[2] < 1 )|| 
      (ver[0] == 3 && ver[1] == 0 && ver[2] == 1 && ver[3] < 73)
     )
  {   
     set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
     if (report_verbosity > 0)
     {
       report = string(
          "\n",
          "HP System Management Homepage version ", version, " appears to be running on\n",
          "the remote host based on the following Server response header :\n",
          "\n",
          "  ", server, "\n"
        );
        security_warning(port:port, extra:report);
      }
      else security_warning(port);
  }
}
