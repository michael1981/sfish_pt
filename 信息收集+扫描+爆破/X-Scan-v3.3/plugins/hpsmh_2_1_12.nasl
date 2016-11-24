#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33548);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2008-1663");
  script_bugtraq_id(30029);
  script_xref(name:"OSVDB", value:"46659");
  script_xref(name:"Secunia", value:"30912");

  script_name(english:"HP System Management Homepage < 2.1.12 Unspecified XSS");
  script_summary(english:"Checks version of HP SMH");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a cross-site scripting
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running HP System Management Homepage
(SMH), a web-based management interface for ProLiant and Integrity
servers. 

The version of HP SMH installed on the remote host fails to sanitize
user input to an unspecified parameter and script before using it to
generate dynamic HTML.  A remote attacker may be able to exploit these
issues to cause arbitrary HTML and script code to be executed by a
user's browser in the context of the affected web site." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/14919" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2008-07/0009.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to HP System Management Homepage v2.1.12 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/www", 2301, 2381);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

# nb: HP only says Linux and Windows are affected - no mention of HP-UX.
os = get_kb_item("Host/OS");
if (!os || ("Windows" >!< os && "Linux" >!< os)) exit(0);


port = get_http_port(default:2301);

# Grab the version from the Server response header.
banner = get_http_banner(port:port);
if (!banner) exit(0);

server = strstr(banner, "Server: ");
server = server - strstr(server, '\r\n');
if ("System Management Homepage/" >< server)
{
  version = strstr(server, "System Management Homepage/") - "System Management Homepage/";

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  # Versions 2.1.10 and 2.1.11 are affected.
  if (ver[0] == 2 && ver[1] == 1 && (ver[2] == 10 || ver[2] == 11))
  {
    if (report_verbosity)
    {
      # Rewrite the version so it's more user-friendly.
      version = string(ver[0], ".", ver[1], ".", ver[2]);
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
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
