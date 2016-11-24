#
# This script was shamelessly copied by Michel Arboi :)
#
# GNU Public License
#

account = "swift";
password = "swift";


include("compat.inc");

if(description)
{
 script_id(12116);
 script_version ("$Revision: 1.11 $");
 script_cve_id("CVE-1999-0502");
 
 script_name(english:"Default Password (swift) for 'swift' Account");
 script_summary(english:"Logs into the remote host");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an account with a default password." );
 script_set_attribute(attribute:"description", value:
"The account 'swift' has the password 'swift'.  An attacker may use it to
gain further privileges on this system." );
 script_set_attribute(attribute:"solution", value:
"Set a password for this account or disable it." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


 script_category(ACT_GATHER_INFO);
 script_family(english:"Default Unix Accounts");
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl", "ssh_detect.nasl");
 script_require_ports("Services/telnet", 23, "Services/ssh", 22);
 exit(0);
}

#
include("default_account.inc");
include('global_settings.inc');

if ( ! thorough_tests && ! get_kb_item("Settings/test_all_accounts")) exit(0);

port = check_account(login:account, password:password);
if(port)security_hole(port);
