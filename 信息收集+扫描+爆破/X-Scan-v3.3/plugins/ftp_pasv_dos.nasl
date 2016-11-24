#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10085);
 script_bugtraq_id(271);
 script_version ("$Revision: 1.25 $");
 script_cve_id("CVE-1999-0079");
 script_xref(name:"OSVDB", value:"958");
 script_xref(name:"Secunia", value:"14285");

 script_name(english:"Multiple Vendor FTP Multiple PASV Command Port Exhaustion DoS");
 script_summary(english:"Determines if a PASV DoS is feasible");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a remote denial of service
vulnerability." );
script_set_attribute(attribute:"description", value:
"The remote FTP server allows users to make any amount of PASV
commands, thus blocking the free ports for legitimate services and
consuming file descriptors. An unauthenticated attacker could exploit
this flaw to crash the FTP service." );
script_set_attribute(attribute:"see_also", value:" http://www.nessus.org/u?c20a7602" );
script_set_attribute(attribute:"solution", value:
"Apply the patches as per the references." );
script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();


 script_category(ACT_ATTACK);

 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 
 script_family(english:"FTP");
 script_dependencie("find_service1.nasl", "ftp_anonymous.nasl");
 script_require_keys("ftp/login");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here :
#

include('ftp_func.inc');
include('global_settings.inc');

if ( report_paranoia < 2 ) exit(0);
port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port))exit(0);

login = get_kb_item("ftp/login");
password = get_kb_item("ftp/password");


if(!login)exit(0);
soc = open_sock_tcp(port);
if(soc)
{
if(ftp_authenticate(socket:soc, user:login, pass:password))
{
 port1 = ftp_pasv(socket:soc);
 for(i=0;i<40;i=i+1)port2 = ftp_pasv(socket:soc);
 if(port1 == port2){
	close(soc);
	exit(0);
	}
 if(port2){
	soc1 = open_sock_tcp(port1, transport:get_port_transport(port));
 	if(soc1>0){
		security_warning(port);
		close(soc1);
		}
	}
} 
close(soc);
}
