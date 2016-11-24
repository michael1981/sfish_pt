#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");
account = "bash";

if(description)
{
 script_id(15583);
 script_version ("$Revision: 1.13 $");
 
 script_name(english:"Unpassworded 'bash' Backdoor Account");
 script_summary(english:"Logs into the remote host with 'bash' account");

 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The remote host has an account with a blank password."
   )
 );

 script_set_attribute(
   attribute:"description",
   value:string(
     "The account 'bash' has no password set. An attacker may use it to gain \n",
     "further privileges on this system. \n",
     "\n",
     "This account was likely created by a backdoor installed by a fake Linux \n",
     "RedHat patch."
   )
 );

 script_set_attribute(
   attribute:"see_also",
   value:string(
     "http://packetstormsecurity.nl/0410-advisories/FakeRedhatPatchAnalysis.txt"
   )
 );

 script_set_attribute(
   attribute:"solution",
   value:string(
     "Disable this account and check your system."
   )
 );

 script_set_attribute(
   attribute:"cvss_vector",
   value:string(
     "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
   )
 );
script_end_attributes();
	     

 script_category(ACT_GATHER_INFO);

 script_family(english:"Backdoors");
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 
 script_dependencies("find_service1.nasl", "ssh_detect.nasl");
 script_require_ports("Services/telnet", 23, "Services/ssh", 22);
 exit(0);
}

include("default_account.inc");
include('global_settings.inc');

if ( ! thorough_tests && ! get_kb_item("Settings/test_all_accounts")) exit(0);

port = check_account(login:account);
if(port)security_hole(port);
