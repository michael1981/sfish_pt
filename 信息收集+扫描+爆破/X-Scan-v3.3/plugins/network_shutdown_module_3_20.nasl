#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(34507);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2008-6816");
  script_bugtraq_id(31933);
  script_xref(name:"OSVDB", value:"50051");
  script_xref(name:"Secunia", value:"32456");

  script_name(english:"EATON MGE Network Shutdown Module < 3.20 Authentication Bypass / Command Execution");
  script_summary(english:"Checks version or tests an action");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by
several issues." );
 script_set_attribute(attribute:"description", value:
"Network Shutdown Module, from EATON MGE Office Protection Systems, is
installed on the remote web server.  It is used to monitor an EATON
UPS and gracefully shutdown the host in the event of a power failure. 

According to its version number, the installation of Network Shutdown
Module on the remote host appears to be earlier than 3.20.  Such
versions fail to require authentication before allowing a remote
attacker to add custom actions through the 'pane_actionbutton.php'
script and then execute them via the 'exec_action.php' script. 

Note that the application runs by default with Administrator
privileges under Windows so successful exploitation of this issue
could result in a complete compromise of the affected system." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2008-10/0205.html" );
 script_set_attribute(attribute:"see_also", value:"http://download.mgeops.com/install/win32/nsm/release_note_nsm_320.txt" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MGE Network Shutdown Module version 3.20 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 4679);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:4679);
if (!get_port_state(port)) exit(0);


# Unless we're paranoid...
if (report_paranoia < 2)
{
  # Make sure it looks like NSM.
  banner = get_http_banner(port:port);
  if (!banner) exit(0);
  if (
    "Server: Pi3Web" >!< banner &&
    "Set-Cookie: NSMID=" >!< banner &&
    "<TITLE>Network Shutdown Module" >!< banner
  ) exit(0);

  # And we're not blocked when trying to test an action.
  res = http_send_recv3(port:port, item:"/exec_action.php?testAction", method:"GET");
  if (res == NULL) exit(0);
  if (res[2] && "Access denied" >< res[2]) exit(0);
}


# Get the version number.
res = http_send_recv3(port:port, item:"/pane_about.php", method:"GET");
if (res == NULL) exit(0);

body = res[2];
if (body && "Network Shutdown Module</B><BR><B>Version: " >< body)
{
  version = strstr(body, "Network Shutdown Module</B><BR><B>Version: ") -
    "Network Shutdown Module</B><BR><B>Version: ";
  version = version - strstr(version, "<BR>");

  if (version && version =~ "^([0-2]\.|3\.([0-9]|[01][0-9])[^0-9])")
  {
    if (report_verbosity)
    {
      report = string(
        "\n",
        "Network Shutdown Module ", version, " appears to be running on the\n",
        "remote host.\n"
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
  }
}
