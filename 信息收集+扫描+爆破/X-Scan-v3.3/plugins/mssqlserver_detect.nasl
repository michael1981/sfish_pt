#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if(description)
{
 script_id(10144);
 script_version ("$Revision: 1.37 $");
 script_name(english:"Microsoft SQL Server TCP/IP Listener Detection");
 
  script_set_attribute(
    attribute:"synopsis",
    value:"A database server is listening on the remote port."
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote host is running MSSQL, a database server from Microsoft.\n",
      "It is possible to extract the version number of the remote\n",
      "installation from the server pre-login response."
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Restrict access to the database to allowed IPs only."
  );
  script_set_attribute(
    attribute:"risk_factor", 
    value:"None"
  );
  script_end_attributes();

 script_summary(english:"Microsoft's SQL TCP/IP listener is running");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 script_family(english:"Service detection");
 script_dependencie("find_service1.nasl", "find_service2.nasl", "mssql_ping.nasl");
 script_require_ports("Services/unknown", 1433);
 exit(0);
}

include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");

if ( thorough_tests && ! get_kb_item("global_settings/disable_service_discovery"))
{
  ports = add_port_in_list(list:get_kb_list("Services/unknown"), port:1433);
}
else ports = make_list(1433);

# Also test any ports we identified via a "Ping" request in mssql_ping.nasl.
possible_ports = get_kb_list("mssql/possible_port");
if (!isnull(possible_ports))
{
  foreach port (make_list(possible_ports))
    ports = add_port_in_list(list:ports, port:port);
}


foreach port (ports)
{
  if (get_port_state(port))
  {
    soc = open_sock_tcp(port);
    if (soc) 
    {
      data =
       mkbyte(0)    + # Type: VERSION
       mkword(0x1a) + # Offset
       mkword(0x06) + # Length

       mkbyte(1)    + # Type: ENCRYPTION
       mkword(0x20) + # Offset
       mkword(0x01) + # Length

       mkbyte(2)    + # Type: INSOPT
       mkword(0x21) + # Offset
       mkword(0x01) + # Length

       mkbyte(3)    + # Type: THREADID
       mkword(0x22) + # Offset
       mkword(0x04) + # Length

       mkbyte(4)    + # Type: MARS
       mkword(0x26) + # Offset
       mkword(0x01) + # Length

       mkbyte(0xFF) + # Type: TERMINATOR

       # UL_VERSION
       mkbyte(12)   + 
       mkbyte(0)    + 
       mkword(0)    +
       # UL_SUBBUILD
       mkword(0)    +

       # B_FENCRYPTION
       mkbyte(0)    + 

       # B_INSTVALIDITY 
       mkbyte(0)    +
     
       # UL_THREADID
       mkdword(0)   +

       # B_MARS
       mkbyte(0)
       ;

      len = strlen(data);

      req = 
          mkbyte(18)    + # Type: Pre-Login Msg
          mkbyte(1)     + # Status: EOM
          mkword(len+8) + # Length: data+header length
          mkword(0)     + # SPID
          mkbyte(0)     + # PacketID
          mkbyte(0)     + # Window (not used)
          data;

      send(socket:soc, data:req);
      buf = recv(socket:soc, length:4096);
      len = strlen(buf);

      if (len < 20) continue;
      code = getbyte(blob:buf, pos:0);
      plen = getword(blob:buf, pos:2);

      if (code != 4 && plen != len) continue;
      pos = 8;

      # parse first option header
      type = getbyte(blob:buf, pos:pos);
      off  = getword(blob:buf, pos:pos+1);
      dlen = getword(blob:buf, pos:pos+3);

      if (type != 0 || (off + dlen) > len || dlen < 6) continue;

      pos += off;

      v[0] = getbyte(blob:buf, pos:pos);
      v[1] = getbyte(blob:buf, pos:pos+1);
      v[2] = getword(blob:buf, pos:pos+2);
      v[3] = getword(blob:buf, pos:pos+4);

      version = string(v[0],".",v[1],".",v[2],".",v[3]);

      set_kb_item(name:"MSSQL/Version", value:version);

      report = string("\nThe remote SQL Server version is ", version, ".");

      security_note(port:port, extra:report);
      register_service(port:port, proto:"mssql");
    }
  }
}
