#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(31096);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2007-6431", "CVE-2007-6148", "CVE-2007-6149");
  script_bugtraq_id(27762);
  script_xref(name:"OSVDB", value:"41538");
  script_xref(name:"OSVDB", value:"41539");
  script_xref(name:"OSVDB", value:"41540");
  script_xref(name:"Secunia", value:"28946");

  script_name(english:"Adobe Flash Media Server < 2.0.5 Multiple Remote Vulnerabilities");
  script_summary(english:"Grabs version from a Server response header");

 script_set_attribute(attribute:"synopsis", value:
"The remote Flash media server is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Adobe's Flash Media Server, an application
server for Flash-based applications. 

The Edge server component included with the version of Flash Media
Server installed on the remote host contains several integer overflow
and memory corruption errors that can be triggered when parsing
specially-crafted Real Time Message Protocol (RTMP) packets.  An
unauthenticated remote attacker can leverage these issues to crash the
affected service or execute arbitrary code with SYSTEM-level
privileges (under Windows), potentially resulting in a complete
compromise of the affected host." );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=662" );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=663" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2008-02/0180.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2008-02/0184.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb08-03.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/documentation/en/flashmediaserver/205/FMS_2_0_5_ReleaseNotes.pdf" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Flash Media Server 2.0.5 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");
  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
  script_dependencies("rtmp_detect.nasl");
  script_require_ports("Services/rtmp", 1935, 19350);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_kb_item("Services/rtmp");
if (!port) port = 1935;
if (!get_port_state(port)) exit(0);


# Send an RTMPT request.
r = http_send_recv3(method:"GET", item:"/fcs/ident", port:port);
if (isnull(r)) exit(0);

# Extract the version number from the server response header.
headers = r[1];
if (
  "Server: FlashCom/" >< headers &&
  # nb: make sure we don't catch FMSAdmin.
  ">Admin user requires valid username and password.<" >!< r[2]
)
{
  server = strstr(headers, "Server:");
  server = server - strstr(server, '\r\n');

  version = strstr(server, "FlashCom/") - "FlashCom/";

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  if (
    ver[0] < 2 ||
    (ver[0] == 2 && ver[1] == 0 && ver[2] < 5)
  )
  {
    if (report_verbosity)
    {
      report = string(
        "\n",
        "According to its Server response header, Flash Media Server version \n",
        version, " is running on the remote host.\n"
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
  }
}
