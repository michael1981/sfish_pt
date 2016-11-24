#
# (C) Tenable Network Security, Inc.
#

account = "jack";


include("compat.inc");

if(description)
{
 script_id(11249);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-1999-0502");
 
 script_name(english:"Unpassworded 'jack' Account");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an account with no password set." );
 script_set_attribute(attribute:"description", value:
"The account 'jack' has no password set. 
An attacker may use it to gain further privileges on this system." );
 script_set_attribute(attribute:"solution", value:
"Set a password for this account or disable it." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();


 script_summary(english:"Logs into the remote host");
 script_category(ACT_GATHER_INFO);

 script_family(english:"Default Unix Accounts");
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 
 
 script_dependencie("find_service1.nasl", "ssh_detect.nasl");
 script_require_ports("Services/telnet", 23, "Services/ssh", 22);
 exit(0);
}

#
# The script code starts here : 
#
include("default_account.inc");
include('global_settings.inc');

if ( ! thorough_tests && ! get_kb_item("Settings/test_all_accounts")) exit(0);

port = check_account(login:account);
if(port)security_hole(port);
