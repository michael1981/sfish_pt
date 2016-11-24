#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(30213);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-1999-0508");

  script_name(english:"MikroTik RouterOS with Blank Password (telnet check)");
  script_summary(english:"Tries to log in as admin");

 script_set_attribute(attribute:"synopsis", value:
"A remote router has no password for its admin account." );
 script_set_attribute(attribute:"description", value:
"The remote host is running MikroTik RouterOS without a password for
its 'admin' account.  Anyone can connect to it and gain administrative
access to it." );
 script_set_attribute(attribute:"see_also", value:"http://www.mikrotik.com/documentation.html" );
 script_set_attribute(attribute:"solution", value:
"Log in to the device and configure a password using the '/password'
command." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
 script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");
  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
  script_dependencies("find_service1.nasl");
  script_require_ports("Services/telnet", 23);

  exit(0);
}


include("telnet_func.inc");


port = get_kb_item("Services/telnet");
if (!port) port = 23;
if (!get_tcp_port_state(port)) exit(0);


banner = get_telnet_banner(port:port);
if (!banner || "MikroTik" >!< banner) exit(0);


user = "admin";
pass = "";


soc = open_sock_tcp(port);
if (soc)
{
  res = telnet_negotiate(socket:soc);
  res += recv_until(socket:soc, pattern:"ogin:");
  if (!res)
  {
    close(soc);
    exit(0);
  }
  send(socket:soc, data:user+'\r\n');

  res = recv_until(socket:soc, pattern:"word:");
  if (!res)
  {
    close(soc);
    exit(0);
  }
  send(socket:soc, data:pass+'\r\n');

  res = recv_until(socket:soc, pattern:"MikroTik RouterOS");
  if (res) security_hole(port);

  close(soc);
}
