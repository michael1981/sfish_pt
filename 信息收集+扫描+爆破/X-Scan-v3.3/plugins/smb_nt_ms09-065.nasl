#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42439);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2009-1127", "CVE-2009-2513", "CVE-2009-2514");
  script_bugtraq_id(36029, 36939, 36941);
  script_xref(name:"OSVDB", value:"59867");
  script_xref(name:"OSVDB", value:"59868");
  script_xref(name:"OSVDB", value:"59869");

  script_name(english:"MS09-065: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Remote Code Execution (969947)");
  script_summary(english:"Checks file version of Win32k.sys");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows kernel is affected by remote privilege escalation
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host contains a version of the Windows kernel that is
affected by multiple vulnerabilities :

  - A NULL pointer dereferencing vulnerability allowing a 
    local user to elevate his privileges (CVE-2009-1127)

  - Insufficient validation of certain input passed to GDI 
    from user mode allows a local user to run arbitrary 
    code in kernel mode. (CVE-2009-2513)

  - A parsing vulnerability when decoding a specially
    crafted Embedded OpenType (EOT) font may allow a remote 
    user to execute arbitrary code on the remote host by 
    luring a user of the remote host into viewing a web 
    page containing such a malformed font. (CVE-2009-2514)"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
Vista and 2008 :

http://www.microsoft.com/technet/security/Bulletin/MS09-065.mspx"
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/11/10"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/11/10"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/11/10"
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


if (hotfix_check_sp(win2k:6, xp:4, win2003:3, vista:3) <= 0) exit(0, "The host is not affected based on its version / service pack.");

if (is_accessible_share())
{
  if (
    # Vista / Windows Server 2008
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"Win32k.sys", version:"6.0.6002.22200", min_version:"6.0.6002.20000", dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"Win32k.sys", version:"6.0.6002.18091",                               dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0", sp:1, file:"Win32k.sys", version:"6.0.6001.22497", min_version:"6.0.6001.20000", dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0", sp:1, file:"Win32k.sys", version:"6.0.6001.18311",                               dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0", sp:0, file:"Win32k.sys", version:"6.0.6000.21108", min_version:"6.0.6000.20000", dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0", sp:0, file:"Win32k.sys", version:"6.0.6000.16908",                               dir:"\system32") ||

    # Windows 2003
    hotfix_is_vulnerable(os:"5.2", sp:2, file:"Win32k.sys", version:"5.2.3790.4571", dir:"\system32") ||

    # Windows XP
    hotfix_is_vulnerable(os:"5.1", sp:3, file:"Win32k.sys", version:"5.1.2600.5863", dir:"\system32") ||
    hotfix_is_vulnerable(os:"5.1", sp:2, file:"Win32k.sys", version:"5.1.2600.3614", dir:"\system32") ||

    # Windows 2000
    hotfix_is_vulnerable(os:"5.0", file:"Win32k.sys", version:"5.0.2195.7322", dir:"\system32")
  )
  {
    set_kb_item(name:"SMB/Missing/MS09-065", value:TRUE);
    hotfix_security_hole();
    hotfix_check_fversion_end();
    exit(0, "Host is missing patch for MS09-065");
  }
  hotfix_check_fversion_end();
  exit(0, "Host is patched");
}
else exit(1, "Could not connect to ADMIN$");
