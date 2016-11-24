#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24903);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2007-1675");
  script_bugtraq_id(23172);
  script_xref(name:"OSVDB", value:"34091");

  script_name(english:"IBM Lotus Domino IMAP Server (nimap.exe) CRAM-MD5 Authentication Remote Overflow");
  script_summary(english:"Checks version of Domino IMAP Server");

 script_set_attribute(attribute:"synopsis", value:
"The remote IMAP server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The IMAP server component of IBM Lotus Domino Server installed on the
remote host fails to check the length of the supplied username in its
CRAM-MD5 authentication mechanism before processing it.  By supplying
a username over 256 bytes, an unauthenticated remote attacker can
leverage this issue to crash the affected service and possibly execute
arbitrary code remotely." );
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-07-011.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2007-03/0370.html" );
 script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg21257028" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Lotus Domino 6.5.6 / 7.0.2 Fix Pack 1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
 script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/imap", 143);

  exit(0);
}


include("imap_func.inc");


port = get_kb_item("Services/imap");
if (!port) port = 143;
if (!get_port_state(port)) exit(0);


# Do a banner check.
banner = get_imap_banner(port:port);
if (!banner || " Domino IMAP4 Server Release " >!< banner) exit(0);

ver = strstr(banner, "Server Release ") - "Server Release ";
ver = ver - strstr(ver, " ready");
if (ver && egrep(pattern:"^(6\.5\.[0-5]($|[^0-9])|7\.0\.([01]($|[^0-9])|2$))", string:ver))
{
  report = strcat('\nAccording to the banner from its IMAP server, Domino ', ver, 
' is\ninstalled on the remote host.\n');
  security_hole(port:port, extra: report);
}
