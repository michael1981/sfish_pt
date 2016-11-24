#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(34158);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2008-3636");
  script_bugtraq_id(31089);
  script_xref(name:"OSVDB", value:"48009");

  script_name(english:"iTunes < 8.0 Integer Buffer Overflow (uncredentialed check)");
  script_summary(english:"Checks version of iTunes in web banner");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by an
integer buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of iTunes installed on the remote Windows host is older
than 8.0.  Such versions include a third-party driver that are
affected by an integer buffer overflow that could allow a local user
to gain system privileges." );
 script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT3025" );
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2008/Sep/msg00001.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to iTunes 8.0 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");
  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
  script_dependencies("itunes_sharing.nasl");
  script_require_ports("Services/www", 3689);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");


port = get_http_port(default:3689);
if (!get_port_state(port)) exit(0);
if (!get_kb_item("iTunes/" + port + "/enabled")) exit(0);


# Do a banner check (if music sharing is enabled and the app is running).
#
# nb: this particular issue only affects Windows installs.
banner = get_http_banner(port:port);
if (!banner) exit(0);

server = strstr(banner, "DAAP-Server:");
server = server - strstr(server, '\n');
if ("iTunes/" >< server && " (Windows)" >< server)
{
  server = chomp(server);
  version = strstr(banner, "iTunes/") - "iTunes/";
  version = version - strstr(version, " (Windows)");
  if (version =~ "^[0-7]\.")
  {
    if (report_verbosity)
    {
      report = string(
        "\n",
        "iTunes version ", version, " is running on the remote host based on the\n",
        "following DAAP-Server response header :\n",
        "\n",
        "  ", server, "\n"
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
  }
}
