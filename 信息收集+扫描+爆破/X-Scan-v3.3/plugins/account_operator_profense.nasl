#
# (C) Tenable Network Security, Inc.
#

account = "operator";
password = "profense";


include("compat.inc");

if(description)
{
 script_id(35559);
 script_version ("$Revision: 1.4 $");

 script_cve_id("CVE-1999-0502");
 
 script_name(english:"Default Password (profense) for 'operator' Account");
 script_summary(english:"Logs into the remote host");
     
 script_set_attribute(attribute:"synopsis", value:
"An account on the remote host uses a known password." );
 script_set_attribute(attribute:"description", value:
"The account 'operator' on the remote host has the password 'profense'. 
An attacker may leverage this issue to gain total control of the
affected system." );
 script_set_attribute(attribute:"solution", value:
"Change the password for this account or disable it." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();


 script_category(ACT_GATHER_INFO);
 script_family(english:"Default Unix Accounts");
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
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

port = check_account(login:account, password:password);
if(port)security_hole(port);
