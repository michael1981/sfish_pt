#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(41061);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2009-2817");
  script_bugtraq_id(36478);
  script_xref(name:"OSVDB", value:"58271");

  script_name(english:"iTunes < 9.0.1 PLS File Buffer Overflow (uncredentialed check)");
  script_summary(english:"Checks version of iTunes");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote host contains an application that is affected by a buffer\n",
      "overflow vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The remote version of iTunes is older than 9.0.1. Such versions are\n",
      "affected by a buffer overflow involving the handling of PLS files.  If\n",
      "an attacker can trick a user on the affected host into opening a\n",
      "malicious PLS file, he can leverage this issue to crash the affected\n",
      "application or to execute arbitrary code on the affected system\n",
      "subject to the user's privileges."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT3884"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2009/sep/msg00006.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/advisories/17952"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to iTunes 9.0.1 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/09/22"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/09/23"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
  script_dependencies("itunes_sharing.nasl");
  script_require_ports("Services/www", 3689);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:3689, embedded:TRUE);
if (!get_kb_item("iTunes/" + port + "/enabled")) exit(1, "The 'iTunes/"+port+"/enabled' KB item is missing.");


# Do a banner check (if music sharing is enabled and the app is running).
banner = get_http_banner(port:port);
if (!banner) exit(1, "get_http_banner() returned NULL for port "+port+".");
if ("DAAP-Server: iTunes/" >!< banner) exit(0, "The banner for port "+port+" is not from iTunes.");

daap = strstr(banner, "DAAP-Server: iTunes/");
daap = daap - strstr(daap, '\r\n');

version = strstr(daap, "DAAP-Server: iTunes/") - "DAAP-Server: iTunes/";
if (" (" >< version) version = version - strstr(version, " (");

ver = split(version, sep:'.', keep:FALSE);
for(i=0;i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 9 ||
  (ver[0] == 9 && ver[1] == 0 && ver[2] < 1)
)
{
  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "iTunes ", version, " appears to be running on the remote host based on the\n",
      "following response header :\n",
      "\n",
      "  ", daap, "\n"
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, "The host is not affected since iTunes "+version+" is installed.");
