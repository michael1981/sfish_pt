#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(32315);
  script_version("$Revision: 1.3 $");

  script_name(english:"Firebird Default Credentials");
  script_summary(english:"Tries to authenticate with default credentials");

 script_set_attribute(attribute:"synopsis", value:
"The remote service is protected with default credentials." );
 script_set_attribute(attribute:"description", value:
"The version of Firebird on the remote host uses default credentials to
control access.  Knowing these, an attacker can gain administrative
access to the affected application." );
 script_set_attribute(attribute:"see_also", value:"http://www.firebirdsql.org/manual/qsg2-config.html" );
 script_set_attribute(attribute:"solution", value:
"Use the application's 'gsec' utility to change the password for the
'SYSDBA' account." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("firebird_detect.nasl");
  script_require_ports("Services/gds_db", 3050);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");


port = get_kb_item("Services/gds_db");
if (!port) port = 3050;
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Variable definitions.
db_user = "SYSDBA";
db_pass = "masterkey";

me = SCRIPT_NAME;
path = "/";
user = "nessus";


# Send a connection request.
req = mkdword(1) +
  mkdword(0x13) +
  mkdword(0x02) +
  mkdword(0x24) +
  mkdword(strlen(path)) +
    path +
    crap(data:raw_string(0), length:((4-(strlen(path)%4)))*(strlen(path)%4>0)) +
  mkdword(2) +
  mkdword(strlen(user+me)+6) +
  mkbyte(0x01) +
    mkbyte(strlen(user)) + 
    user +
  mkbyte(0x04) +
    mkbyte(strlen(me)) + 
    me +
  mkbyte(6) + mkbyte(0) +
    crap(data:raw_string(0), length:((4-((6+strlen(me+user))%4)))*((6+strlen(me+user))%4>0)) +
  mkdword(8) +
    mkdword(1) +
    mkdword(2) +
    mkdword(3) +
    mkdword(2) +
    mkdword(0x0a) +
    mkdword(1) +
    mkdword(2) +
    mkdword(3) +
    mkdword(4);
send(socket:soc, data:req);
res = recv(socket:soc, length:16);


# If the response contains an accept opcode...
if (strlen(res) == 16 && getdword(blob:res, pos:0) == 3)
{
  dpb = 
    mkbyte(1) +
    mkbyte(0x1c) +
    mkbyte(strlen(db_user)) +
      db_user +
    mkbyte(0x1d) +
    mkbyte(strlen(db_pass)) +
      db_pass;

  # Try to create the database.
  #
  # nb: '/' isn't a valid name and so the database isn't actually created.
  req = mkdword(0x14) +
    mkdword(0) +
    mkdword(strlen(path)) +
      path +
      crap(data:raw_string(0), length:((4-(strlen(path)%4)))*(strlen(path)%4>0)) +
    mkdword(strlen(dpb)) + dpb;
  req += crap(data:raw_string(0), length:((4-(strlen(req)%4)))*(strlen(req)%4>0));
  send(socket:soc, data:req);
  res = recv(socket:soc, length:64);

  # There's a problem if we get a response with an error involving CreateFile.
  if (
    strlen(res) >= 16 &&
    getdword(blob:res, pos:0) == 9 &&
    (
      "CreateFile (" >< res ||
      "open O_CREAT" >< res
    )
  ) 
  {
    if (report_verbosity)
    {
      report = string(
        "\n",
        "Nessus was able to gain access using the following credentials :\n",
        "\n",
        "  User     : ", db_user, "\n",
        "  Password : ", db_pass, "\n"
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
  }
}
close(soc);
