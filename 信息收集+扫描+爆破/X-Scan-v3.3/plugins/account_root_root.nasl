#
# (C) Tenable Network Security, Inc.
#

account = "root";
password = "root";


include("compat.inc");

if(description)
{
 script_id(11255);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CVE-1999-0502");
 
 script_name(english:"Default Password (root) for 'root' Account");
     
 script_set_attribute(attribute:"synopsis", value:
"An account on the remote host uses a known password." );
 script_set_attribute(attribute:"description", value:
"The account 'root' on the remote host has the password 'root. An 
attacker may leverage this issue to gain total control of the affected 
system." );
 script_set_attribute(attribute:"solution", value:
"Change the password for this account or disable it." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Logs into the remote host with root/root");

 script_category(ACT_GATHER_INFO);
 script_family(english:"Default Unix Accounts");
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_dependencie("ssh_detect.nasl", "telnetserver_detect_type_nd_version.nasl");
 script_require_ports("Services/telnet", 23, "Services/ssh", 22);
 exit(0);
}

#
# The script code starts here : 
#
include("default_account.inc");

port = check_account(login:account, password:password);
if(port)security_hole(port);
