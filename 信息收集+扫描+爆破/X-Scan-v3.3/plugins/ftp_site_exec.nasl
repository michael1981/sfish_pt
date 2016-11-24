#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10090);
 script_bugtraq_id(2241);
 script_version ("$Revision: 1.25 $");
 script_cve_id("CVE-1999-0080",
 	 	"CVE-1999-0955"  # If vulnerable to the flaw above, it's 
				 # automatically vulnerable to this one
				 # too...
		 
		 );
 script_xref(name:"OSVDB", value:"77");
 script_xref(name:"OSVDB", value:"8719");
 script_xref(name:"OSVDB", value:"8720");
 script_name(english:"WU-FTPD SITE EXEC Arbitrary Local Command Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a command execution
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of WU-FTPD that is affected by a
command execution vulnerability. It is possible to execute arbitrary
command son the remote host using the 'site exec' FTP problem." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/1995_3/0000.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WU-FTPD 2.4 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 script_summary(english:"Attempts to write on the remote root dir");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencie("find_service1.nasl", "ftp_anonymous.nasl");
 script_require_keys("ftp/login");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#

include('ftp_func.inc');
port = get_kb_item("Services/ftp");
if(!port)port = 21;

if(get_port_state(port))
{
login = get_kb_item("ftp/login");
password = get_kb_item("ftp/password");


if(login)
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 if(ftp_authenticate(socket:soc, user:login,pass:password))
 {
 data = string("SITE exec /bin/sh -c /bin/id\n");
 send(socket:soc, data:data);
 reply = recv_line(socket:soc,length:1024);
 if("uid" >< reply){
        set_kb_item(name:"ftp/root_via_site_exec", value:TRUE);
        security_hole(port);
	}
 else {
        data = string("SITE exec /bin/sh -c /usr/bin/id\n");
        send(socket:soc, data:data);
        reply = recv_line(socket:soc, length:1024);
        if("uid" >< reply){
                security_hole(port);
                set_kb_item(name:"ftp/root_via_site_exec", value:TRUE);
                }
      }
 data = string("QUIT\n");
 send(socket:soc, data:data);
 }
close(soc);
}
}


