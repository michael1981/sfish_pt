#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10481);  
 script_version ("$Revision: 1.40 $");
 script_cve_id("CVE-2004-1532");
 script_bugtraq_id(11704);
 script_xref(name:"OSVDB", value:"380");

 script_name(english:"MySQL Unpassworded Account Check");

 script_set_attribute(attribute:"synopsis", value:
"The remote database server can be accessed without a password." );
 script_set_attribute(attribute:"description", value:
"It is possible to connect to the remote MySQL database server using an
unpassworded account.  This may allow an attacker to launch further
attacks against the database." );
 script_set_attribute(attribute:"solution", value:
"Disable or set a password for the affected account." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


 summary["english"] = "Checks for unpassword root / anonymous accounts";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"Databases");
 script_require_ports("Services/mysql", 3306);
 script_dependencies("find_service2.nasl");
 exit(0);
}

include ("byte_func.inc");

global_var packet_number;

function parse_length_number (blob)
{
 return make_list (
		ord(blob[0]) + (ord(blob[1]) << 8) + (ord(blob[2]) << 16),
		ord(blob[3])
		);
}

function null_ascii (s)
{
 return s + mkbyte(0);
}

function mysql_packet (data)
{
 local_var len, tmp;

 len = strlen(data);
 tmp = raw_string (len & 0xFF,  (len>>8) & 0xFF, (len>>16) & 0xFF, packet_number) + data;
 packet_number++;

 return tmp;
}

function mysql_auth_req (name)
{
 return mkword (0x05a4)             + # Flags
        mkbyte (0) + mkword (0)     + # Max packet
        null_ascii (s:name);
}

function mysql_query (query)
{
 return mkbyte(3) + query;

}

function mysql_show_databases_request (socket)
{
 local_var req, buf, databases, loop;

 packet_number = 0;
 req = mysql_packet (data:mysql_query(query:"show databases"));

 databases = make_list ();

 send (socket:socket, data:req);
 buf = recv_mysql_packet (socket:socket);
 if (!isnull(buf) && (getbyte (blob:buf, pos:0) == 1))
 {
  buf = recv_mysql_packet (socket:socket);
  if (!isnull(buf))
  {
   buf = recv_mysql_packet (socket:socket);
   if (!isnull(buf) && (getbyte(blob:buf, pos:0) == 254))
   {
    loop = 1;
    while (loop)
    {
     buf = recv_mysql_packet (socket:socket);
     if (!isnull(buf) && (getbyte(blob:buf, pos:0) != 254))
       databases = make_list (databases, substr(buf, 1, strlen(buf)-1));
     else
       loop = 0;
    }
   }
  }    
 }

 if (max_index(databases) > 0)
   return databases;
 else
  return NULL;
}

function recv_mysql_packet (socket)
{
 local_var len, packet_info, buf;

 len = recv (socket:socket, length:4, min:4);
 if (strlen (len) != 4)
   return NULL;

 packet_info = parse_length_number (blob:len);

 if ((packet_info[0] > 65535) || (packet_info[1] != packet_number))
   return NULL;

 packet_number ++;

 buf = recv (socket:socket, length:packet_info[0], min:packet_info[0]);
 if (strlen(buf) != packet_info[0])
   return NULL;

 return buf;
}


## Main code ##

port = get_kb_item("Services/mysql");
if (!port)
  port = 3306;

if (!get_port_state(port))
  exit (0);


foreach name (make_list("root", "anonymous"))
{
 packet_number = 0;

 soc = open_sock_tcp (port);
 if (!soc)
   exit (0);

 buf = recv_mysql_packet (socket:soc);
 if (isnull(buf) || (getbyte(blob:buf, pos:0) != 10))
   exit (0);

 req = mysql_packet (data:mysql_auth_req (name:name));

 send (socket:soc, data:req);
 buf = recv_mysql_packet (socket:soc);
 if (isnull(buf))
   exit (0);

 error_code = getbyte (blob:buf, pos:0);
 if (error_code == 0)
 {
  report = string("\nThe '", name, "' account does not have a password.\n");

  databases = mysql_show_databases_request (socket:soc);
  if (!isnull(databases))
  {
   info = "";
   foreach value (databases)
   {
    info += string("  - ", value, "\n");
   }
   if (info)
   {
    report += string(
      "\n",
      "Here is the list of databases on the remote server :\n",
      "\n",
      info
    );
    set_kb_item(name: 'MySQL/no_passwd/'+port, value: name);
   }
  }
  security_hole(port:port, extra:info);
  exit(0);
 }

 close (soc);
}
