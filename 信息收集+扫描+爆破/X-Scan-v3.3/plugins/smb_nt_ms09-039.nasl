#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40558);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2009-1923", "CVE-2009-1924");
  script_bugtraq_id(35980, 35981);
  script_xref(name:"OSVDB", value:"56899");
  script_xref(name:"OSVDB", value:"56900");

  script_name(english: "MS09-039: Vulnerabilities in WINS Could Allow Remote Code Execution (969883)");
  script_summary(english:"Determines the presence of update 969883");

  script_set_attribute(
    attribute:"synopsis",
    value:"Arbitrary code can be executed on the remote host through the WINS service"
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote host has a Windows WINS server installed.\n",
      "\n",
      "The remote version of this server contains two vulnerabilities that may allow\n",
      "an attacker to execute arbitrary code on the remote system:\n",
      "\n",
      "- One heap overflow vulnerability can be exploited by any attacker\n",
      "\n",
      "- One integer overflow vulnerability can be exploited by a WINS replication\n",
      "partner.\n",
      "\n",
      "An attacker may use these flaws to execute arbitrary code on the remote system with\n",
      "SYSTEM privileges.\n"
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Microsoft has released a set of patches for Windows 2000 and 2003 :\n",
      "\n",
      "http://www.microsoft.com/technet/security/Bulletin/MS09-039.mspx"
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


if (hotfix_check_sp(win2k:6, win2003:3) <= 0) exit(0);
if ( ! get_kb_item("SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Services/WINS/DisplayName") ) exit(0);

if (is_accessible_share())
{
  if (

    # Windows Server 2003
    hotfix_is_vulnerable(os:"5.2", file:"Wins.exe", version:"5.2.3790.4520", dir:"\System32") ||
    # Windows 2000
    hotfix_is_vulnerable(os:"5.0", file:"Wins.exe", version:"5.0.2195.7300", dir:"\System32")
  )
  {
    set_kb_item(name:"SMB/Missing/MS09-039", value:TRUE);
    hotfix_security_hole();
  }
  hotfix_check_fversion_end(); 
}
