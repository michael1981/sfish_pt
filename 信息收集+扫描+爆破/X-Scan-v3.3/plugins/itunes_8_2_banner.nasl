#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(38986);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2009-0950");
  script_bugtraq_id(35157);
  script_xref(name:"OSVDB", value:"54833");

  script_name(english:"iTunes < 8.2 itms: URI Handling Overflow (uncredentialed check)");
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
      "The remote version of iTunes is older than 8.2. Such versions are\n",
      "affected by a stack-based buffer overflow that can be triggered\n",
      "when parsing 'itms:' URLs.  If an attacker can trick a user on the\n",
      "affected host into clicking on a malicious link, he can leverage\n",
      "this issue to crash the affected application or to execute arbitrary\n",
      "code on the affected system subject to the user's privileges."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT3592"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2009/jun/msg00001.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to iTunes 8.2 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
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
  (ver[0] == 8 && ver[1] < 2)
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
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
