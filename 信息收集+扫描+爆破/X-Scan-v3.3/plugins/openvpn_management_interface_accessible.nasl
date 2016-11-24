#
# (C) Tenable Network Security
#



include("compat.inc");

if (description)
{
  script_id(21330);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2006-2229");
  script_xref(name:"OSVDB", value:"25660");

  script_name(english:"OpenVPN Unprotected Management Interface");
  script_summary(english:"Looks for banner of OpenVPN Management Interface");

 script_set_attribute(attribute:"synopsis", value:
"The remote VPN server can be managed remotely without authentication." );
 script_set_attribute(attribute:"description", value:
"The remote host is running OpenVPN, an open-source SSL VPN. 

The version of OpenVPN installed on the remote host does not require
authentication to access the server's management interface.  An
attacker can leverage this issue to gain complete control over the
affected application simply by telneting in." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/432863/30/60/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://openvpn.net/management.html" );
 script_set_attribute(attribute:"solution", value:
"Disable the management interface or bind it only to a specific
address, such as 127.0.0.1." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:P" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 7505);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


# nb: there is no default port, but the documentation uses 7505.
if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery")  ) {
  port = get_unknown_svc(7505);
  if (!port) exit(0);
}
else port = 7505;
if (!port || !get_tcp_port_state(port)) exit(0);


# Check the server's banner.
banner = get_kb_item("Banner/"+port);
if (banner && "OpenVPN Management Interface Version" >< banner)
  security_warning(port);
