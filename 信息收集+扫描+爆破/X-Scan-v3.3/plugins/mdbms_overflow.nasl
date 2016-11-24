#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10422);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-2000-0446");
 script_bugtraq_id(1252);
 script_xref(name:"OSVDB", value:"324");
 
 script_name(english:"MBDMS Database Server Long String Remote Overflow");
 script_summary(english:"Checks the remote MDBMS version");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote database server has a buffer overflow vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "According to its banner, the remote host is running a beta version\n",
     "of MDBMS.  It is very likely this version has a remote buffer\n",
     "overflow vulnerability.  A remote attacker could exploit this to\n",
     "crash the service, or execute arbitrary code."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2000-05/0274.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of this software."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Gain a shell remotely");

 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");

 script_require_ports(2223, 2224);
 exit(0);
}


include('global_settings.inc');

if ( report_paranoia < 2 ) exit(0);

port = 2224;
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc){
	port = 2223;
	if ( get_port_state(port) )
	 {
	 soc = open_sock_tcp(port);
	 if(!soc)exit(0);
	 }
	else exit(0);
	}

r = recv_line(socket:soc, length:1024);
close(soc);
if(ereg(pattern:"^.*MDBMS V0\..*", string:r))
{
security_hole(port);
}


