#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(31737);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2008-1483");
  script_bugtraq_id(28444);
  script_xref(name:"Secunia", value:"29522");
  script_xref(name:"OSVDB", value:"43745");

  script_name(english:"OpenSSH X11 Forwarding Session Hijacking");
  script_summary(english:"Checks OpenSSH server version");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote SSH service is prone to an X11 session hijacking
vulnerability." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of SSH installed on the remote
host is older than 5.0.  Such versions may allow a local user to
hijack X11 sessions because it improperly binds TCP ports on the local
IPv6 interface if the corresponding ports on the IPv4 interface are in
use." );
 script_set_attribute(attribute:"see_also", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=463011" );
 script_set_attribute(attribute:"see_also", value:"http://www.openssh.org/txt/release-5.0" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH version 5.0 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");
 
  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}


include("backport.inc");
include("global_settings.inc");


port = get_kb_item("Services/ssh");
if (!port) port = 22;
if (!get_port_state(port)) exit(0);


# Check the version in the banner.
banner = get_kb_item("SSH/banner/" + port);
if (!banner) exit(0);

nbanner = tolower(get_backport_banner(banner:banner));
if (nbanner =~ "openssh[-_][0-4]\." && ! backported )
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "The remote OpenSSH server returned the following banner :\n",
      "\n",
      "  ", banner, "\n"
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
