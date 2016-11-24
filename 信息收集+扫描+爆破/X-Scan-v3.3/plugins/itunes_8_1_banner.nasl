#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35914);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2009-0016", "CVE-2009-0143");
  script_bugtraq_id(34094);
  script_xref(name:"OSVDB", value:"52578");
  script_xref(name:"OSVDB", value:"52579");

  script_name(english:"iTunes < 8.1 Multiple Vulnerabilities (uncredentialed check)");
  script_summary(english:"Checks version of iTunes");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that may be affected by
multiple vulerabilites.");

  script_set_attribute(attribute:"description", value:
"According to its banner, the version of iTunes installed on the remote
host is older than 8.1.  Such versions may be affected by multiple
vulnerabilities :

  - It may be possible to cause a denial of service by
    sending a maliciously crafted DAAP header to the
    application. Note that this flaw only affects iTunes
    running on a Windows host. (CVE-2009-0016)

  - When subscribing to a podcast an authentication dialog
    may be presented without clarifying the origin of the
    authentication request. An attacker could exploit this
    flaw in order to steal the user's iTunes credentials.
    (CVE-2009-0143)");

  script_set_attribute(attribute:"see_also", value:
    "http://support.apple.com/kb/HT3487");
  script_set_attribute(attribute:"see_also", value:
   "http://lists.apple.com/archives/security-announce/2009/Mar/msg00001.html");

  script_set_attribute(attribute:"solution", value:
    "Upgrade to iTunes 8.1 or later.");

  script_set_attribute(attribute:"cvss_vector", value:
    "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");
  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
  script_dependencies("itunes_sharing.nasl");
  script_require_ports("Services/www", 3689);

  exit(0);
}


include("global_settings.inc");
include("http.inc");
include("misc_func.inc");


port = get_http_port(default:3689);
if (!get_port_state(port)) exit(0);
if (!get_kb_item("iTunes/" + port + "/enabled")) exit(0);

# Do a banner check (if music sharing is enabled and the app is running).
banner = get_http_banner(port:port);
if (!banner) exit(0);
if ("DAAP-Server: iTunes/" >!< banner) exit(0);

daap = strstr(banner, "DAAP-Server: iTunes/");
daap = daap - strstr(daap, '\r\n');

version = strstr(daap, "DAAP-Server: iTunes/") - "DAAP-Server: iTunes/";
if (" (" >< version) version = version - strstr(version, " (");

ver = split(version, sep:'.', keep:FALSE);
for(i=0;i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if(
  ver[0] < 8 ||
  (ver[0] == 8 && ver[1] < 1)
)
{
  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "iTunes version ", version, " appears to be running on the remote host based on\n",
      "the following response header :\n",
      "\n",
      "  ", daap, "\n"
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
