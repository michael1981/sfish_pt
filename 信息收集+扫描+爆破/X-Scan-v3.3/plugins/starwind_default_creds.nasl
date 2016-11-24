#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(29701);
  script_version("$Revision: 1.2 $");

  script_name(english:"StarWind Control Port Default Credentials");
  script_summary(english:"Logs into the StarWind control port with default credentials");

 script_set_attribute(attribute:"synopsis", value:
"The remote service is protected with default credentials." );
 script_set_attribute(attribute:"description", value:
"The remote StarWind control port is configured to use the default
credentials to control access.  Knowing these, an attacker can gain
administrative control of the affected application." );
 script_set_attribute(attribute:"solution", value:
"Edit the StarWind configuration file and change the login credentials
in the authentication section.  Then, restart the service to put the
changes into effect." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/starwind_ctl", 3261);

  exit(0);
}


include("byte_func.inc");
include("misc_func.inc");


port = get_kb_item("Services/starwind_ctl");
if (!port) port = 3261;
if (!get_port_state(port)) exit(0);


user = "test";
pass = "test";


# Establish a connection and read the banner.
soc = open_sock_tcp(port);
if (!soc) exit(0);

banner = recv(socket:soc, length:1024, min:24);
if (strlen(banner) == 0 || "StarWind iSCSI Target" >!< banner) exit(0);


# Try to authenticate.
send(socket:soc, data:string("login ", user, " ", pass, "\r\n"));
res = recv(socket:soc, length:1024, min:5);
if (strlen(res) && stridx(res, "200 Completed") == 0)
{
  report = string(
    "Nessus was able to gain access using the following credentials :\n",
    "\n",
    "  User Name : ", user, "\n",
    "  Password  : ", pass, "\n"
  );

  # Collect some info about the remote devices.
  send(socket:soc, data:'list -what:"devices"\r\n');
  res = recv(socket:soc, length:1024, min:5);
  if (strlen(res) && stridx(res, "200 Completed.") == 0)
  {
    info = strstr(res, "200 Completed.") - "200 Completed.";
    info = str_replace(find:'\n', replace:'\n  ', string:info);

    report += '\n' +
      'In addition, it collected the following information about the\n' +
      'devices on the remote host.\n' +
      info;
  }

  security_hole(port:port, extra:report);
}
send(socket:soc, data: 'quit\r\n');
close(soc);
