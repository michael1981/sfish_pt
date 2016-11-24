#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(20218);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2005-2938");
  script_bugtraq_id(15446);
  script_xref(name:"OSVDB", value:"20988");

  script_name(english:"iTunes For Windows iTunesHelper.exe Path Subversion Local Privilege Escalation (uncredentialed check)");
  script_summary(english:"Checks for an local code execution vulnerability in iTunes for Windows");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by a local
code execution flaw." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of iTunes for Windows on the
remote host launches a helper application by searching for it through
various system paths.  An attacker with local access can leverage this
issue to place a malicious program in a system path and have it called
before the helper application." );
 script_set_attribute(attribute:"see_also", value:"http://www.idefense.com/application/poi/display?id=340&type=vulnerabilities" );
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2005/Nov/msg00001.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to iTunes 6 for Windows or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_dependencies("itunes_sharing.nasl");
  script_require_ports("Services/www", 3689);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");


port = get_http_port(default:3689);
if (!get_port_state(port)) exit(0);

if ( ! get_kb_item("iTunes/" + port + "/enabled") ) exit(0);


# Do a banner check (if music sharing is enabled).
banner = get_http_banner(port:port);
if (!banner) exit(0);
# nb: only Windows is affected.
if (egrep(pattern:"^DAAP-Server: iTunes/[0-5]\..+Windows", string:banner)) {
  security_hole(port);
}

