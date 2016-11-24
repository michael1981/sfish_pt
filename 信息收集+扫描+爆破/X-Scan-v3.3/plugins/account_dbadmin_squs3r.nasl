#
# (C) Tenable Network Security, Inc.
#


account = "dbadmin";
password = "sq!us3r";


include("compat.inc");


if (description)
{
  script_id(42147);
  script_version("$Revision: 1.1 $");

  script_xref(name:"Secunia", value:"36971");
 
  script_name(english:"Default Password (sq!us3r) for 'dbadmin' Account");
  script_summary(english:"Tries to log into the remote host");
     
  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote system can be accessed with a default account."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The account 'dbadmin' on the remote host has the password 'sq!us3r'.\n",
      "An attacker may leverage this issue to gain access to the affected\n",
      "system.\n",
      "\n",
      "Note that RioRey RIOS appliances, used for dynamic denial of service\n",
      "mitigation, are reported to use these credentials to support\n",
      "connections from rVIEW, the vendor's central management and\n",
      "configuration tool, and that an attacker reportedly may be able to\n",
      "escalate privileges through several vulnerabilities to gain full\n",
      "control over the device."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://packetstormsecurity.org/0910-exploits/riorey-passwd.txt"
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "If the affected device is a RioRey platform, contact the vendor for a\n",
      "patch.\n",
      "\n",
      "Otherwise, change the password for this account or disable it."
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/10/07"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/10/05"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/10/15"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Default Unix Accounts");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
  script_dependencies("find_service1.nasl", "ssh_detect.nasl");
  script_require_ports("Services/telnet", 23, "Services/ssh", 22, 8022);

  exit(0);
}


include("default_account.inc");
include("global_settings.inc");

if (!thorough_tests) exit(1, "Thorough tests must be enabled for this plugin to run.");
if (!get_kb_item("Settings/test_all_accounts")) exit(1, "The 'Settings/test_all_accounts' KB item is missing.");


port = check_account(login:account, password:password);
if (port) security_hole(port);
