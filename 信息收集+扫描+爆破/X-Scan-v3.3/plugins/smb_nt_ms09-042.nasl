#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40561);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2009-1930");
  script_bugtraq_id(35993);
  script_xref(name:"OSVDB", value:"56904");

  script_name(english:"MS09-042: Vulnerability in Telnet Could Allow Remote Code Execution (960859)");
  script_summary(english:"Checks version of Telnet.exe");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "Arbitrary code can be executed on the remote host through the remote\n",
      "Telnet client."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
     "The remote Telnet client does not correctly opt in to NTLM credential-\n",
      "reflection protections, which ensure that a user's credentials are not\n",
      "reflected back and used against the user.\n",
      "\n",
      "If a remote attacker can trick a user on the host into connecting to a \n",
      "malicious server with an affected version of the Telnet client, he can\n",
      "leverage this issue to gain the rights of that user and do anything\n",
      "that he has privileges to do."
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Microsoft has released a set of patches for Windows 2000, XP, 2003,\n",
      "Vista and 2008 :\n",
      "\n",
      "\n",
      "http://www.microsoft.com/technet/security/Bulletin/MS09-042.mspx"
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/08/11"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/08/11"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/08/11"
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


include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");


if (hotfix_check_sp(win2k:6, xp:4, win2003:3, vista:3) <= 0) exit(0, "Host is not affected based on its version / service pack.");
if (!is_accessible_share()) exit(1, "is_accessible_share() failed.");


if (
  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Telnet.exe", version:"6.0.6002.22150", min_version:"6.0.6002.20000", dir:"\System32") ||
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Telnet.exe", version:"6.0.6002.18049",                               dir:"\System32") ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"Telnet.exe", version:"6.0.6001.22447", min_version:"6.0.6001.20000", dir:"\System32") ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"Telnet.exe", version:"6.0.6001.18270",                               dir:"\System32") ||
  hotfix_is_vulnerable(os:"6.0", sp:0,             file:"Telnet.exe", version:"6.0.6000.21065", min_version:"6.0.6000.20000", dir:"\System32") ||
  hotfix_is_vulnerable(os:"6.0", sp:0,             file:"Telnet.exe", version:"6.0.6000.16868",                               dir:"\System32") ||

  # Windows 2003
  hotfix_is_vulnerable(os:"5.2", sp:2,             file:"Telnet.exe", version:"5.2.3790.4528", dir:"\System32") ||

  # Windows XP
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Telnet.exe", version:"5.1.2600.5829", dir:"\System32") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x64", file:"Telnet.exe", version:"5.2.3790.4528", dir:"\System32") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Telnet.exe", version:"5.1.2600.3587", dir:"\System32") ||

  # Windows 2000
  hotfix_is_vulnerable(os:"5.0",                   file:"Telnet.exe", version:"5.0.33670.4", dir:"\System32")
)
{
  set_kb_item(name:"SMB/Missing/MS09-042", value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end(); 
  exit(0);
}
else
{
  hotfix_check_fversion_end(); 
  exit(0, "The host is not affected.");
}
