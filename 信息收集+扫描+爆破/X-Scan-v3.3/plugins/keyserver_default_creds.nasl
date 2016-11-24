#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(27041);
  script_version("$Revision: 1.4 $");

  script_name(english:"K2 KeyServer Default Credentials");
  script_summary(english:"Tries to login to KeyServer with default credentials");
 script_set_attribute(attribute:"synopsis", value:
"The remote service is protected with default credentials." );
 script_set_attribute(attribute:"description", value:
"The remote K2 KeyServer installation is configured to use default
credentials to control access.  Knowing these, an attacker can gain
control of the affected application." );
 script_set_attribute(attribute:"solution", value:
"Change the password for the 'Administrator' account using
KeyConfigure." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );


script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/k2-keyserver", 19283);

  exit(0);
}


include("byte_func.inc");
include("misc_func.inc");


port = get_kb_item("Services/k2-keyserver");
if (!port) port = 19283;
if (!get_port_state(port)) exit(0);


user = "Administrator";
pass = "Sassafras";


# Establish a connection and read the banner.
soc = open_sock_tcp(port);
if (!soc) exit(0);

banner = recv(socket:soc, length:1024, min:5);
if (strlen(banner) == 0 || stridx(banner, "/0 0 ") != 0) exit(0);


# Try to authenticate.
send(socket:soc, data:string("USER ", user, "\r\n"));
res = recv(socket:soc, length:1024, min:5);
if (strlen(res) && stridx(res, "/0 0 OK") == 0)
{
  send(socket:soc, data:string("PASS ", pass, "\r\n"));
  res = recv(socket:soc, length:1024, min:5);
  if (strlen(res) && stridx(res, "/0 0 OK") == 0)
  {
    report = string(
      "Nessus was able to gain access using the following credentials :\n",
      "\n",
      "  User Name : ", user, "\n",
      "  Password  : ", pass, "\n"
    );
    security_hole(port:port, extra:report);
  }
}
send(socket:soc, data:string("QUIT\r\n"));
close(soc);
