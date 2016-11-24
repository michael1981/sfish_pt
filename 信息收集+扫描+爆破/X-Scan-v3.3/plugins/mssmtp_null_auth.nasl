#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if(description)
{
 script_id(11308);
 script_version ("$Revision: 1.16 $");

 script_cve_id("CVE-2002-0054");
 script_bugtraq_id(4205);
 script_xref(name:"OSVDB", value:"5390");
 script_xref(name:"OSVDB", value:"10247");
 
 script_name(english:"Microsoft Windows SMTP Service NTLM Null Session Authorization Bypass (uncredentialed check)");
 script_summary(english:"Checks SMTP authentication");
 
 script_set_attribute(
  attribute:"synopsis",
  value:string(
   "The remote SMTP server is affected by an authorization bypass\n",
   "vulnerability."
  )
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "It is possible to authenticate to the remote SMTP service by logging\n",
   "in with a NULL session. \n",
   "\n",
   "An attacker may use this flaw to use your SMTP server as a spam relay."
  )
 );
 script_set_attribute(
  attribute:"solution", 
  value:"http://www.microsoft.com/technet/security/bulletin/MS02-011.mspx"
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"SMTP problems");
 script_dependencie("smtpserver_detect.nasl");
 script_exclude_keys("SMTP/wrapped");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#


include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port)port = 25;
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 data = smtp_recv_banner(socket:soc); 
 if ( ! data ||  "Microsoft" >!< data  ) exit(0);
 crp = string("HELO example.com\r\n");
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:1024);
 if(!(ereg(pattern:"^250 .*", string:data)))exit(0);
 
 send(socket:soc, data:string("AUTH NTLM TlRMTVNTUAABAAAAB4IAgAAAAAAAAAAAAAAAAAAAAAA=\r\n"));
 r = recv_line(socket:soc, length:4096);
 if(!ereg(string:r, pattern:"^334 .*"))exit(0);
 send(socket:soc, data:string("TlRMTVNTUAADAAAAAQABAEAAAAAAAAAAQQAAAAAAAABAAAAAAAAAAEAAAAAAAAAAQAAAAAAAAABBAAAABYIAAAA=\r\n"));
 r = recv_line(socket:soc, length:4096);
 if(ereg(string:r, pattern:"^235 .*"))security_warning(port);
}
