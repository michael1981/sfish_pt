#
# (C) Tenable Network Security, Inc.
#

# References:
# Date:	 Wed, 20 Mar 2002 11:35:04 +0100 (CET)
# From:	"Wojciech Purczynski" <cliph@isec.pl>
# To: bugtraq@securityfocus.com, vulnwatch@vulnwatch.org
# CC: security@isec.pl
# Subject: Bypassing libsafe format string protection
# 
# TBD: Add those tests:
#	printf("%'n", &target);
#	printf("%In", &target);
#	printf("%2$n", "unused argument", &target);
#



include("compat.inc");

if(description)
{
 script_id(11133);
 script_version ("$Revision: 1.15 $");
 
 script_name(english: "Remote Service Format String (Generic Check)");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to execute code on the remote host." );
 script_set_attribute(attribute:"description", value:
"Nessus killed the remote service by sending it specially 
crafted data. The remote service seems to be vulnerable to 
a format string attack. An attacker might use this flaw to 
make it crash or even execute arbitrary code on this host." );
 script_set_attribute(attribute:"solution", value:
"Upgrade your software or contact your vendor and 
inform him of this vulnerability." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english: "Generic format string attack");
 script_category(ACT_DESTRUCTIVE_ATTACK); 
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english: "Misc.");
 script_dependencie("find_service1.nasl", "find_service2.nasl");
 script_require_ports("Services/unknown");
 exit(0);
}

#

include('misc_func.inc');

port = get_unknown_svc();
if (! port) exit(0);


if (! get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(0);

send(socket: soc, data: "xxxxxxxxxxxxxxxxxxxxxxxxxx");
close(soc);

soc = open_sock_tcp(port);
if (! soc) exit(0);
send(socket: soc, 
	data: crap(data:"%#0123456x%04x%x%s%p%n%d%o%u%c%h%l%q%j%z%Z%t%i%e%g%f%a%C%S%04x%%#0123456x%%x%%s%%p%%n%%d%%o%%u%%c%%h%%l%%q%%j%%z%%Z%%t%%i%%e%%g%%f%%a%%C%%S%%04x",
		length:256) );
close(soc);


for (i = 0; i < 3; i ++)
{
 soc = open_sock_tcp(port);
 if (soc)
 {
  close(soc);
  exit(0);
 }
 sleep(1);
}

security_hole(port);
exit(0);

