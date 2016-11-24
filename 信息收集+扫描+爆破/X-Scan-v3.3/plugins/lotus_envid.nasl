#
# (C) Tenable Network Security, Inc.
#

# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
# and was modified and tested by Vanja Hrustic <vanja@relaygroup.com>


include("compat.inc");

if(description)
{
 script_id(10543);
 script_version ("$Revision: 1.23 $");
 script_cve_id("CVE-2000-1047");
 script_bugtraq_id(1905);
 script_xref(name:"OSVDB", value:"442");
 
 script_name(english:"Lotus Domino SMTP ENVID Variable Handling Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote SMTP server is affected by a remote buffer overflow 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote Domino SMTP server is vulnerable to a buffer overflow when 
supplied a too long ENVID variable within a MAIL FROM command.

An attacker may use this flaw to prevent Domino services from working 
properly, or to execute arbitrary code on this host." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?34705b38" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Lotus Notes/Domino 5.0.6 or later, is this reportedly fixes
the issue." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Determines if the remote Domino server is vulnerable to a buffer overflow");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english:"SMTP problems");
 script_dependencie("find_service1.nasl", "smtp_settings.nasl");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port)port = 25;

if(get_port_state(port))
{
  soc = open_sock_tcp(port);
  if(soc)
  {
    r = smtp_recv_banner(socket:soc);
    if(!r)exit(0);
    
    if("omino" >< r)
    {
    domain = get_kb_item("Settings/third_party_domain");
    req = string("HELO ", domain, "\r\n");
    send(socket:soc, data:req);
    r  = recv_line(socket:soc, length:4096);

    req = string("MAIL FROM: <nessus@", domain, "> ENVID=", crap(300), "\r\n");
    send(socket:soc, data:req);
    r = recv_line(socket:soc, length:4096);

    if(ereg(pattern:"^250 ", string:r))
        security_hole(port);
    }
    close(soc);
   }
}
