#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(24757);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2006-6336");
  script_bugtraq_id(21897);
  script_xref(name:"OSVDB", value:"32587");

  script_name(english:"Eudora WorldMail Mail Management Server (MAILMA.exe) Remote Overflow");
  script_summary(english:"Tries to access WorldMail MAILMA service");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Eudora WorldMail, a commercial mail server
for Windows. 

According to its banner, the version of Eudora Worldmail installed on
the remote host contains a heap buffer overflow flaw in its Mail
Management Agent.  Using a specially-crafted request, an
unauthenticated remote attacker may be able to leverage this issue to
crash the affected service or execute arbitrary code on the remote
host.  Since the service runs with LOCAL SYSTEM privileges by default,
this could lead to a complete compromise of the affected host." );
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-07-001.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2007-01/0137.html" );
 script_set_attribute(attribute:"solution", value:
"Either block access to the affected port or switch to another product
as the vendor is rumoured to have said it will not release a fix." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
  script_dependencies("find_service1.nasl");
  script_require_ports("Services/mailma", 106);

  exit(0);
}


include("misc_func.inc");


port = get_kb_item("Services/mailma");
if (!port) port = 106;
if (!get_tcp_port_state(port)) exit(0);


banner = get_service_banner_line(service:"mailma", port:port);
if (
  banner && 
  # nb: don't worry about the banner -- there's no fix.
  egrep(pattern:"^[0-9][0-9][0-9] .*WorldMail Mail Management Server", string:banner)
) security_hole(port);
