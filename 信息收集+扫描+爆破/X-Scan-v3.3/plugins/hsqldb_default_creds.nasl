#
# (C) Tenable Network Security
#



include("compat.inc");

if (description)
{
  script_id(23731);
  script_version("$Revision: 1.3 $");

  script_name(english:"HSQLDB Server Default Credentials");
  script_summary(english:"Checks for default credentials with an HSQLDB server");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a database server with default credentials." );
 script_set_attribute(attribute:"description", value:
"The installation of HSQLDB on the remote host has the default 'sa'
account enabled without a password.  An attacker may use this flaw to
execute commands against the remote host, as well as read any data it
might contain." );
 script_set_attribute(attribute:"solution", value:
"Disable this account or assign a password to it.  In addition, it is
suggested that you filter incoming traffic to this port." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies ("hsqldb_detect.nasl");
  script_require_ports("Services/hsqldb", 9001);

  exit(0);
}


port = get_kb_item("Services/hsqldb");
if (!port) port = 9001;
if (!get_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Try to login with default credentials.
user = toupper("sa");                   # default username
pass = toupper("");                     # default password
db = "";

req = raw_string(
                                        # packet size, to be added later
  0x00, 0x01, 0x00, 0x07,               # ???, perhaps a version number
  0x00, 0x00, 0x00, 0x00,               # ???
  0x00, 0x00, 0x00, 0x00,               # ???
  0x00, 0x00, 0x00, strlen(user), user, # user
  0x00, 0x00, 0x00, strlen(pass), pass, # pass
  0x00, 0x00, 0x00, strlen(db), db,     # database name
  0x00, 0x00, 0x00, 0x00                # ???
);
req = raw_string(
  0x00, 0x00, 0x00, (strlen(req)+4),    # packet size, as promised
  req
);
send(socket:soc, data:req);
res = recv(socket:soc, length:64);
if (res == NULL) exit(0);


# There's a problem if we were able to authenticate.
if (
  strlen(res) == 20 && 
  raw_string(
    0x00, 0x00, 0x00, 0x14, 
    0x00, 0x00, 0x00, 0x01, 
    0x00, 0x00, 0x00, 0x00
  ) >< res
) security_hole(port);
