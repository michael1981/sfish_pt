#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10539);
 script_version ("$Revision: 1.35 $");
 script_cve_id("CVE-1999-0024");
 script_bugtraq_id(136, 678);
 script_xref(name:"OSVDB", value:"438");

 script_name(english:"DNS Server Recursive Query Cache Poisoning Weakness");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote name server allows recursive queries to be performed
by the host running nessusd." );
 script_set_attribute(attribute:"description", value:
"It is possible to query the remote name server for third party 
names.

If this is your internal nameserver, then ignore this warning.

If you are probing a remote nameserver, then it allows anyone
to use it to resolve third party names (such as www.nessus.org).
This allows attackers to perform cache poisoning attacks against 
this nameserver.

If the host allows these recursive queries via UDP, then the 
host can be used to 'bounce' Denial of Service attacks against 
another network or system." );
 script_set_attribute(attribute:"see_also", value:"http://www.cert.org/advisories/CA-1997-22.html" );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/library/cc787602%28WS.10%29.aspx" );
 script_set_attribute(attribute:"solution", value:
"Restrict recursive queries to the hosts that should
use this nameserver (such as those of the LAN connected to it).

If you are using bind 8, you can do this by using the instruction
'allow-recursion' in the 'options' section of your named.conf.

If you are using bind 9, you can define a grouping of internal addresses
using the 'acl' command.

Then, within the options block, you can explicitly state:
'allow-recursion { hosts_defined_in_acl }'

If you are using another name server, consult its documentation." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 
 script_summary(english:"Determines if the remote name server allows recursive queries");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english: "DNS");
 script_dependencie("smtp_settings.nasl", "dns_server.nasl");
 script_require_ports("DNS/udp/53");
 exit(0);
}

#
# We ask the nameserver to resolve www.<user_defined_domain>
#
include('global_settings.inc');
include("dns_func.inc");
include("byte_func.inc");
include('network_func.inc');

if (! COMMAND_LINE && ! get_kb_item('DNS/udp/53') &&
    !get_kb_item('Services/dns') && !get_kb_item('Services/udp/dns') )
{
 debug_print('No DNS service found. Exiting\n');
 exit(0);
}

host = "www";
domain = get_kb_item("Settings/third_party_domain");
if(!domain)domain = "nessus.org";

host += "." + domain;
req = mk_query(txt:dns_str_to_query_txt(host), type:0x0001, class:0x001);

dns["transaction_id"] = rand() % 65535; # Random
dns["flags"]  = 0x0100;	# Standard query, recursion desired
dns["q"]      = 1;	# 1 Q
dns["an_rr"]  = 0;
dns["au_rr"]  = 0;
dns["ad_rr"]  = 0;

req = mkdns(dns:dns, query:req);
soc = open_sock_udp(53);

send(socket:soc, data:req);
r  = recv(socket:soc, length:4096);
close(soc);

if (strlen(r) > 0)
{
pk = dns_split(r);

if ( (pk["flags"] & 0x8085) == 0x8080 )
 {
 if (! is_private_addr()) security_warning(port:53, proto:"udp");
 set_kb_item(name:"DNS/recursive_queries", value:TRUE);
 }
exit(0);
}

# No answer. Packets may have been lost

port = get_kb_item('Services/dns');
if (! port) port = 53;
if (! get_port_state(port)) exit(0);
soc = open_sock_tcp(port);
if (! soc) exit(0);

debug_print('No packet received on UDP. Trying TCP port ', port, '\n');

send(socket:soc, data: htons(n: strlen(req)));
send(socket: soc, data: req);
r  = recv(socket:soc, length: 2, min: 2);
if (strlen(r) == 2) 
{
 len = ntohs(n: r);
 r = recv(socket: soc, length: len, min: len);
}
else
 r = '';

close(soc);
if (strlen(r) > 0)
{
pk = dns_split(r);

if ( (pk["flags"] & 0x8085) == 0x8080 )
 {
 if (! is_private_addr()) security_warning(port:53, proto: 'tcp');
 set_kb_item(name:"DNS/recursive_queries", value:TRUE);
 }
exit(0);
}
