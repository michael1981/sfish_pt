#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(30186);
  script_version("$Revision: 1.3 $");

  script_name(english:"WinComLPD LPD Monitoring Server Default Credentials");
  script_summary(english:"Tries to log into WinComLPD LPD Monitoring Server with default credentials");

 script_set_attribute(attribute:"synopsis", value:
"The remote service is protected with default credentials." );
 script_set_attribute(attribute:"description", value:
"The remote LPD Monitoring Server port is configured to use the default
credentials to control access.  Knowing these, an attacker can gain
administrative control of the affected application." );
 script_set_attribute(attribute:"solution", value:
"Edit the application's 'lpdservice.ini' file and change the
credentials in the 'GENERAL CONFIGURE' section.  Then, restart the
service to put the changes into effect." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("wincomlpd_lpdservice_detect.nasl");
  script_require_ports("Services/lpdservice", 13500);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


port = get_kb_item("Services/lpdservice");
if (!port) port = 13500;
if (!get_port_state(port)) exit(0);


# Establish a connection.
soc = open_sock_tcp(port);
if (!soc) exit(0);


# Try to authenticate.
set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

cmd = 0x03e9;
user = "admin";
pass = "admin";
domain = "";

req = 
  mkdword(1) + 
  mkdword(2) +
  mkbyte(strlen(user)) + user +
  mkbyte(strlen(pass)) + pass +
  mkbyte(strlen(domain)) + domain +
  mkbyte(5) + mkbyte(4) +
  mkword(0);
req = 
  mkdword(0) +
  mkword(0) + 
  mkword(cmd) +
  mkword(0) +
  mkword(strlen(req)) + req;
send(socket:soc, data:req);
res = recv(socket:soc, length:12, min:4);
close(soc);


# If the response looks right...
if (
  strlen(res) == 12 &&
  getword(blob:res, pos:6) == (0x8000 + cmd) &&
  getword(blob:res, pos:8) == 0x7dd &&
  getword(blob:res, pos:10) == 0
)
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "Nessus was able to gain access using the following credentials :\n",
      "\n",
      "  Username : ", user, "\n",
      "  Password : ", pass, "\n"
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
