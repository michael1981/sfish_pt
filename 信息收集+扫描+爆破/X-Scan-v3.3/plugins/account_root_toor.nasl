#
# (C) Tenable Network Security, Inc.
#

account = "root";
password = "toor";

include("compat.inc");

if(description)
{
 script_id(35777);
 script_version ("$Revision: 1.4 $");

 script_cve_id("CVE-1999-0502");
 script_xref(name:"OSVDB", value:"56382");
 
 script_name(english:"Default Password (toor) for 'root' Account");
     
 script_set_attribute(attribute:"synopsis", value:
"An account on the remote host uses a known password." );
 script_set_attribute(attribute:"description", value:
"The account 'root' on the remote host has the password 'toor'. An 
attacker may leverage this issue to gain total control of the affected 
system." );
 script_set_attribute(attribute:"solution", value:
"Change the password for this account or disable it." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Logs into the remote host with root/toor");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Default Unix Accounts");
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_dependencie("ssh_detect.nasl", "telnetserver_detect_type_nd_version.nasl");
 script_require_ports("Services/telnet", 23, "Services/ssh", 22);
 exit(0);
}

#
# The script code starts here : 
#
include("default_account.inc");
include("global_settings.inc");

if ( ! thorough_tests && ! get_kb_item("Settings/test_all_accounts")) exit(0);

port = check_account(login:account, password:password);
if(port)security_hole(port);
