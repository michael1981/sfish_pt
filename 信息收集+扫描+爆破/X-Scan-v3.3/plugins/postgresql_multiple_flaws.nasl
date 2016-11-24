#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 
 script_id(11456);  
 script_version ("$Revision: 1.14 $");

 script_cve_id("CVE-2002-1397", "CVE-2002-1398", "CVE-2002-1399", "CVE-2002-1400", "CVE-2002-1401", "CVE-2002-1402");
 script_bugtraq_id(5497, 5527, 6610, 6611, 6612, 6613, 6614, 6615, 7075);
 script_xref(name:"OSVDB", value:"6190");
 script_xref(name:"OSVDB", value:"6191");
 script_xref(name:"OSVDB", value:"8998");
 script_xref(name:"OSVDB", value:"9504");
 script_xref(name:"OSVDB", value:"9505");
 script_xref(name:"OSVDB", value:"11829");
 script_xref(name:"OSVDB", value:"11830");
 script_xref(name:"OSVDB", value:"11831");
 script_xref(name:"RHSA", value:"RHSA-2003:0010-10");

 script_name(english:"PostgreSQL < 7.2.3 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary commands may be run on the remote server." );
 script_set_attribute(attribute:"description", value:
"The remote PostgreSQL server, according to its version number, is 
vulnerable to various flaws which may allow an attacker who has the
rights to query the remote database to obtain a shell on this host." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to postgresql 7.2.3 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english: "Attempts to log into the remote PostgreSQL daemon");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english: "Databases");
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/postgres", 5432);
 exit(0);
}
include("global_settings.inc");
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
     if(ereg(string:r, pattern:"PostgreSQL ([0-6]\.|7\.(2\.[0-2])|([0-1]\..*)).*")){
     	security_warning(port);
	}
     }
    else if("ERROR: function version()" >< r)security_warning(port);
    exit(0);
   }
}

soc = open_sock_tcp(port);
if(!soc)exit(0);
send(socket:soc, data:string("xx\r\n"));
r = recv(socket:soc, length:6);
close(soc);
if("EFATAL" >< r)
{
 if ( report_paranoia < 2 ) exit(0);
 security_warning(port:port, extra: "
Nessus was not able to remotely determine the version of the remote 
PostgreSQL server, so this might be a false positive.
");
}
