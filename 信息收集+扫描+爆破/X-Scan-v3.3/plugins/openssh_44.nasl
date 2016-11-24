#
# (C) Tenable Network Security
#



include("compat.inc");

if (description) 
{
  script_id(22466);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2006-5051", "CVE-2006-5052");
  script_bugtraq_id(20241, 20245);
  script_xref(name:"OSVDB", value:"29264");
  script_xref(name:"OSVDB", value:"29266");

  name["english"] = "OpenSSH < 4.4 Multiple GSSAPI Vulnerabilities";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote SSH server is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of OpenSSH installed on the
remote host contains a race condition that may allow an
unauthenticated remote attacker to crash the service or, on portable
OpenSSH, possibly execute code on the affected host.  In addition,
another flaw exists that may allow an attacker to determine the
validity of usernames on some platforms. 

Note that successful exploitation of these issues requires that GSSAPI
authentication be enabled." );
 script_set_attribute(attribute:"see_also", value:"http://www.openssh.com/txt/release-4.4" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH 4.4 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  summary["english"] = "Checks version number of OpenSSH";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}


include("backport.inc");


port = get_kb_item("Services/ssh");
if (!port) port = 22;


auth = get_kb_item("SSH/supportedauth/" + port);
if (!auth) exit(0);
if ("gssapi" >!< auth) exit(0);


banner = get_kb_item("SSH/banner/" + port);
if (banner)
{
  banner = tolower(get_backport_banner(banner:banner));
  if (banner =~ "openssh[-_]([0-3]\.|4\.[0-3]([^0-9]|$))")
    security_hole(port);
}
