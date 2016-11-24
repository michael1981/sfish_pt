#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(21783);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2006-1467");
  script_bugtraq_id(18730);
  script_xref(name:"OSVDB", value:"26909");

  script_name(english:"iTunes AAC File Parsing Integer Overflow (uncredentialed check)");
  script_summary(english:"Check the version of iTunes"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by a remote
code execution flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running iTunes, a popular jukebox program. 

The remote version of iTunes is vulnerable to an integer overflow when
it parses a specially crafted AAC file.  By tricking a user into
opening such a file, a remote attacker may be able to leverage this
issue to execute arbitrary code on the affected host, subject to the
privileges of the user running the application." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/10781" );
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2006/Jun/msg00001.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to iTunes 6.0.5 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
  script_dependencies("itunes_sharing.nasl");
  script_require_ports("Services/www", 3689);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:3689);
if (!get_port_state(port)) exit(0);
if (!get_kb_item("iTunes/" + port + "/enabled")) exit(0);


# Do a banner check (if music sharing is enabled and the app is running).
banner = get_http_banner(port:port);
if (
  banner && 
  egrep(pattern:"^DAAP-Server: iTunes/([0-5]\.|6\.0\.[0-4][^0-9]?)", string:banner)
) security_warning(port);
