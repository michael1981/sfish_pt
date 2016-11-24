#
# (C) Tenable Network Security, Inc.
#

account = "admin";
password = "password";


include("compat.inc");

if(description)
{
 script_id(35660);
 script_version("$Revision: 1.3 $");
 script_cve_id("CVE-1999-0502");
 
 script_name(english:"Default Password (password) for 'admin' Account");
     
 script_set_attribute(
  attribute:"synopsis",
  value:string(
   "The remote system can be accessed with a default administrator\n",
   "account."
  )
 );
 script_set_attribute(
  attribute:"description",
  value:string(
   "The account 'admin' on the remote host has the password 'password'.\n",
   "An attacker may leverage this issue to gain access, likely as an\n",
   "administrator, to the affected system."
  )
 );
 script_set_attribute(
  attribute:"solution", 
  value:"Change the password for this account or disable it."
 );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
 script_end_attributes();

 script_summary(english:"Logs into the remote host");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Default Unix Accounts");
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl", "ssh_detect.nasl", "bcm96338_admin_password.nasl");
 script_require_ports("Services/telnet", 23, "Services/ssh", 22);
 exit(0);
}

#
# The script code starts here : 
#
include("default_account.inc");
include("global_settings.inc");

if ( ! thorough_tests && ! get_kb_item("Settings/test_all_accounts")) exit(0);
if (get_kb_item('bcm96338/default_telnet_credential')) exit(0);

port = check_account(login:account, password:password);
if(port)security_hole(port);
