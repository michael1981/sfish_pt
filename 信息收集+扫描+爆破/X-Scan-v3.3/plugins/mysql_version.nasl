#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10719); 
 script_version ("$Revision: 1.24 $");

 script_name(english:"MySQL Server Detection");

desc_access["english"] = "
Synopsis :

A database server is listening on the remote port. 

Description :

The remote host is running MySQL, an open-source database server.  It
is possible to extract the version number of the remote installation
from the server greeting. 

Solution :

Restrict access to the database to authorized IPs only.

Risk factor :

None";

 script_set_attribute(attribute:"synopsis", value:
"A database server is listening on the remote port." );
 script_set_attribute(attribute:"description", value:
"The remote host is running MySQL, an open-source database server.  The
remote database access is restricted and configured to reject access
from unauthorized IPs.  Therefore it was not possible to extract its
version number." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );

script_end_attributes();

 script_summary(english:"MySQL Server detection");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"Databases");
 script_require_ports("Services/mysql", 3306);
 script_dependencies("find_service1.nasl");
 exit(0);
}

include ("global_settings.inc");
include ("misc_func.inc");

function parse_length_number (blob)
{
 return make_list (
		ord(blob[0]) + (ord(blob[1]) << 8) + (ord(blob[2]) << 16),
		ord(blob[3])
		);
}


function get_null_string (blob, pos)
{
 local_var i, tmp;

 tmp = NULL;

 for (i=pos; i<strlen(blob); i++)
 {
  if (ord(blob[i]) != 0)
    tmp += blob[i];
  else
    break;
 }

 return tmp;
}


port = get_kb_item("Services/mysql");
if (!port)
  port = 3306;

if (!get_port_state(port))
  exit (0);

soc = open_sock_tcp (port);
if (!soc)
  exit (0);

len = recv (socket:soc, length:4);
if (strlen (len) != 4)
  exit (0);

packet_info = parse_length_number (blob:len);

if ((packet_info[0] > 65535) || (packet_info[1] != 0))
  exit (0);

buf = recv (socket:soc, length:packet_info[0]);
if (strlen(buf) != packet_info[0])
  exit (0);

protocol = ord(buf[0]);

if (protocol == 255)
{
 if ("is not allowed to connect to this MySQL server" >< buf)
 {
  security_note(port:port);
  register_service(port:port, proto:"mysql");
 }
 exit(0);
}

if (protocol == 10)
{
 version = get_null_string (blob:buf, pos:1);
 set_mysql_version (port:port, version:version);

 report = string ("The remote MySQL version is ", version);

 security_note(port:port, extra:report);
 register_service(port:port, proto:"mysql");
}
