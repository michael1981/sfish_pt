#
# (C) Tenable Network Security, Inc.
#


account = "root";
password = "admin";


include("compat.inc");


if (description)
{
  script_id(40355);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-1999-0502");
 
  script_name(english:"Default Password (admin) for 'root' Account");
  script_summary(english:"Tries to log into the remote host");
     
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
      "The account 'root' on the remote host has the password 'admin'.\n",
      "An attacker may leverage this issue to gain access, likely as an\n",
      "administrator, to the affected system.\n",
      "\n",
      "Note that DD-WRT, an open source Linux-based firmware popular on\n",
      "small routers and embedded systems, is known to use these\n",
      "credentials by default."
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Change the password for this account or disable it."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/07/23"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Default Unix Accounts");
  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
  script_dependencie("find_service1.nasl", "ssh_detect.nasl");
  script_require_ports("Services/telnet", 23, "Services/ssh", 22);
  exit(0);
}


include("default_account.inc");
include("global_settings.inc");

if ( ! thorough_tests && ! get_kb_item("Settings/test_all_accounts")) exit(0);

port = check_account(login:account, password:password);
if (port) security_hole(port);
