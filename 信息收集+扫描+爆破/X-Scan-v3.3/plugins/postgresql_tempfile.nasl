#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
#  Ref: Trustix security engineers
#
#  This script is released under the GNU GPL v2
#
# Changes by Tenable:
# - Revised plugin-title (1/07/2009)


include("compat.inc");

if(description)
{
 
 script_id(15417);  
 script_version ("$Revision: 1.9 $");
 script_cve_id("CVE-2004-0977");
 script_bugtraq_id(11295);
 script_xref(name:"OSVDB", value:"10941");

 script_name(english:"PostgreSQL make_oidjoins_check Arbitrary File Overwrite");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote service is vulnerable to an unspecified flaw." );
 script_set_attribute(attribute:"description", value:
"The remote PostgreSQL server, according to its version number, is vulnerable 
to an unspecified insecure temporary file creation flaw, which may allow 
a local attacker to overwrite arbitrary files with the privileges of 
the application." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to newer version of this software." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N" );


script_end_attributes();

 
 script_summary(english:"Attempts to log into the remote PostgreSQL daemon");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"Databases");
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/postgres", 5432);
 exit(0);
}


port = get_kb_item("Services/postgres");
if(!port)port = 5432;

if(!get_port_state(port))exit(0);

#
# Request the database 'template1' as the user 'postgres' or 'pgsql'
# 
zero = raw_string(0x00);

user[0] = "postgres";
user[1] = "pgsql";

for(i=0;i<2;i=i+1)
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 usr = user[i];
 len = 224 - strlen(usr);

 req = raw_string(0x00, 0x00, 0x01, 0x28, 0x00, 0x02,
    	         0x00, 0x00, 0x74, 0x65, 0x6D, 0x70, 0x6C, 0x61,
		 0x74, 0x65, 0x31) + crap(data:zero, length:55) +
        usr +
       crap(data:zero, length:len);

 send(socket:soc, data:req);
 r = recv(socket:soc, length:5);
 r2 = recv(socket:soc, length:1024);
 if((r[0]=="R") && (strlen(r2) == 10))
  {
    dbs = "";
    req = raw_string(0x51) + "select version();" + 
    	  raw_string(0x00);
    send(socket:soc, data:req);
    
    r = recv(socket:soc, length:65535);
    r = strstr(r, "PostgreSQL");
    if(r != NULL)
     {
      for(i=0;i<strlen(r);i++)
      {
       if(ord(r[i]) == 0)
     	break;
       }
     r = substr(r, 0, i - 1);
     if(ereg(string:r, pattern:"PostgreSQL ([0-6]\.|7\.(4\.[0-5])|([0-3]\..*)).*")){
     	security_note(port);
	exit(0);
	}
     }
    exit(0);
   }
}
