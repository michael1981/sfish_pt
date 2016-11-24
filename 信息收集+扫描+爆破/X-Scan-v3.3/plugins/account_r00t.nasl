#
# (C) Tenable Network Security, Inc.
#
# See the Nessus Scripts License for details
#

account = "r00t";


include("compat.inc");

if(description)
{
 script_id(34083);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-1999-0502");
 
 script_name(english: "Unpassworded 'r00t' account");

 script_set_attribute(attribute:"synopsis", value:
"An account on the remote host does not have a password." );
 script_set_attribute(attribute:"description", value:
"The account 'r00t' on the remote host has no password.  An attacker
may leverage this issue to gain access to the affected system and
launch further attacks against it." );
 script_set_attribute(attribute:"solution", value:
"Set a password for this account or disable it." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();


 script_summary(english:"Logs into the remote host");
 script_category(ACT_GATHER_INFO);

 script_family(english:"Default Unix Accounts");
 
 script_copyright(english:"This script is Copyright (C) 2008 Tenable Network Security, Inc.");
  
 script_dependencie("find_service1.nasl", "ssh_detect.nasl");
 script_require_ports("Services/telnet", 23, "Services/ssh", 22);
 exit(0);
}

#
# The script code starts here : 
#
include("default_account.inc");
include("global_settings.inc");
if ( ! thorough_tests && ! get_kb_item("Settings/test_all_accounts")) exit(0);

port = check_account(login:account);
if(port)security_hole(port);
