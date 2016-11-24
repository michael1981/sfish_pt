#
# (C) Tenable Network Security, Inc.
#

# Should cover bid 7345
#
# See the Nessus Scripts License for details
#
# Services known to crash or freeze on too much data:
# Calisto Internet Talker Version 0.04 and prior
#
################
# References
################
#
# From: "subversive " <subversive@linuxmail.org>
# To: bugtraq@securityfocus.com, vulnwatch@vulnwatch.org
# Date: Mon, 25 Nov 2002 09:33:49 +0800
# Subject: SFAD02-002: Calisto Internet Talker Remote DOS
#


include("compat.inc");

if(description)
{
 script_id(10735);
 script_version ("$Revision: 1.30 $");

 script_name(english:"Generic Overflow Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"It might be possible to execute arbitrary code on this host.");
 script_set_attribute(attribute:"description", value:
"It was possible to crash the remote service by flooding it with too much
data.

An attacker may use this flaw to make this service crash continuously, 
preventing this service from working properly. It may also be possible
to exploit this flaw to execute arbitrary code on this host." );
 script_set_attribute(attribute:"solution", value:
"Contact your vendor and inform it of this vulnerability.
Upgrade your sofware." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );


script_end_attributes();

 script_summary(english: "Flood against the remote service");
 
 # Maybe we should set this to ACT_DESTRUCTIVE_ATTACK only?
 if (ACT_FLOOD) script_category(ACT_FLOOD);
 else		script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 script_family(english:"General");
 script_dependencie("find_service2.nasl");
 script_require_ports("Services/unknown");
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

#
include("global_settings.inc");
include('misc_func.inc');

if (report_paranoia < 2) exit(0);

port = get_unknown_svc();
if (! port) exit(0);
if (! get_port_state(port)) exit(0);

to = get_read_timeout();

soc = open_sock_tcp(port);
if (! soc) exit(0);

 r = recv(socket:soc, length:4096);
 if(!r) has_banner = 0;
 else has_banner = 1;
 if(!has_banner)
 {
   send(socket:soc, data: 'HELP\r\n');
   r = recv(socket:soc, length:4096);
   if(r)replies_to_help = 1;
   else replies_to_help = 0;
 }

 close(soc);


 soc = open_sock_tcp(port);
 if ( soc )
 {
 send(socket:soc, data:crap(65535)) x 10;
 close(soc);
 }
 
for (i = 1; i < 4; i ++)
{
 soc = open_sock_tcp(port);
 if (soc) break;
 else sleep(i);
}

 if(!soc)
 {
  security_hole(port:port, extra:'It was not possible to re-open the connection this port');
 }
 else
 {
  if(has_banner)
  {
   r = recv(socket:soc, length:4096, timeout: 3 * to);
   if(!r) {
    security_hole(port:port, extra:'This service used to display a banner, but does not anymore.');
   }
  }
  else
  {
   if(replies_to_help)
   {
    send(socket:soc, data: 'HELP\r\n');
    r =  recv(socket:soc, length:4096, timeout: 3 * to);
    if(!r)
    {
     security_hole(port:port, extra:'This service used to reply to the \'HELP\' command, but does not anymore.');
    }
   }
  }
 }

