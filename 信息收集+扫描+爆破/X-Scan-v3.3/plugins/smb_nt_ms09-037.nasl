#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40556);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2008-0015", "CVE-2008-0020", "CVE-2009-0901", "CVE-2009-2493", "CVE-2009-2494");
  script_bugtraq_id(35558, 35585, 35828, 35832, 35982);
  script_xref(name:"OSVDB", value:"55651");
  script_xref(name:"OSVDB", value:"56272");
  script_xref(name:"OSVDB", value:"56696");
  script_xref(name:"OSVDB", value:"56698");
  script_xref(name:"OSVDB", value:"56910");

  script_name(english:"MS09-037: Vulnerabilities in Microsoft Active Template Library (ATL) Could Allow Remote Code Execution (973908)");
  script_summary(english:"Checks version of various files");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "Arbitrary code can be executed on the remote host through Microsoft\n",
      "Active Template Library."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote Windows host contains a version of the Microsoft Active\n",
      "Template Library (ATL), included as part of Visual Studio or Visual\n",
      "C++, that is affected by multiple vulnerabilities :\n",
      "\n",
      "  - A remote code execution issue affects the Microsoft\n",
      "    Video ActiveX Control due to the a flaw in the function\n",
      "    'CComVariant::ReadFromStream' used in the ATL header,\n",
      "    which fails to properly restrict untrusted data read\n",
      "    from a stream. (CVE-2008-0015)\n",
      "\n",
      "  - A remote code execution issue exists in the Microsoft\n",
      "    Active Template Library due to an error in the 'Load'\n",
      "    method of the 'IPersistStreamInit' interface, which\n",
      "    could allow calls to 'memcpy' with untrusted data.\n",
      "    (CVE-2008-0020)\n",
      "\n",
      "  - An issue in the ATL headers could allow an attacker to\n",
      "    force VariantClear to be called on a VARIANT that has\n",
      "    not been correctly initialized and, by supplying a\n",
      "    corrupt stream, to execute arbitrary code.\n",
      "    (CVE-2009-0901)\n",
      "\n",
      "  - Unsafe usage of 'OleLoadFromStream' could allow\n",
      "    instantiation of arbitrary objects which can bypass\n",
      "    related security policy, such as kill bits within\n",
      "    Internet Explorer. (CVE-2009-2493)\n",
      "\n",
      "  - A bug in the ATL header could allow reading a variant\n",
      "    from a stream and leaving the variant type read with\n",
      "    an invalid variant, which could be leveraged by an\n",
      "    attacker to execute arbitrary code remotely.\n",
      "    (CVE-2009-2494)"
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Microsoft has released a set of patches for Windows 2000, XP, 2003,\n",
      "Vista and 2008 :\n",
      "\n",
      "http://www.microsoft.com/technet/security/Bulletin/MS09-037.mspx"
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
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
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}



include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


if (!get_kb_item("SMB/WindowsVersion")) exit(1, "The 'SMB/WindowsVersion' KB item is missing.");
if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "The 'SMB/Registry/Enumerated' KB item is missing.");

if (hotfix_check_sp(win2k:6, xp:4, win2003:3, vista:3) <= 0) exit(0, "Host is not affected based on its version / service pack.");
if (!is_accessible_share()) exit(1, "is_accessible_share() failed.");


# Media Player.
if (
  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Wmp.dll", version:"11.0.6002.22172", min_version:"11.0.6002.20000", dir:"\System32") ||
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Wmp.dll", version:"11.0.6002.18065",                                dir:"\System32") ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"Wmp.dll", version:"11.0.6001.7114",  min_version:"11.0.6001.7100",  dir:"\System32") ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"Wmp.dll", version:"11.0.6001.7007",                                 dir:"\System32") ||
  hotfix_is_vulnerable(os:"6.0", sp:0,             file:"Wmp.dll", version:"11.0.6000.6511",  min_version:"11.0.6000.6500",  dir:"\System32") ||
  hotfix_is_vulnerable(os:"6.0", sp:0,             file:"Wmp.dll", version:"11.0.6000.6352",                                 dir:"\System32") ||


  # Windows 2003
  hotfix_is_vulnerable(os:"5.2", sp:2,             file:"Wmp.dll", version:"10.0.0.4006",                                    dir:"\System32") ||

  # Windows XP
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Wmp.dll", version:"9.0.0.4507",                                     dir:"\System32") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x64", file:"Wmp.dll", version:"11.0.5721.5268",  min_version:"11.0.0.0",        dir:"\System32") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x64", file:"Wmp.dll", version:"10.0.0.4006",                                    dir:"\System32") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Wmp.dll", version:"9.0.0.3271",                                     dir:"\System32") ||

  # Windows 2000
  hotfix_is_vulnerable(os:"5.0",                   file:"Wmp.dll", version:"9.0.0.3364",                                     dir:"\System32")
)
{
  set_kb_item(name:"SMB/Missing/MS09-037", value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end(); 
  exit(0);
}

# ATL.
if (
  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Atl.dll", version:"3.5.2284.2",                               dir:"\System32") ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Atl.dll", version:"3.5.2284.2",                               dir:"\System32") ||
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"Atl.dll", version:"3.5.2284.2",                               dir:"\System32") ||

  # Windows 2003
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Atl.dll", version:"3.5.2284.2", dir:"\System32") ||

  # Windows XP
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Atl.dll", version:"3.5.2284.2", dir:"\System32") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, file:"Atl.dll", version:"3.5.2284.2", dir:"\System32") ||

  # Windows 2000
  hotfix_is_vulnerable(os:"5.0",       file:"Atl.dll", version:"3.0.9793.0", dir:"\System32")
)
{
  set_kb_item(name:"SMB/Missing/MS09-037", value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end(); 
  exit(0);
}


# MSWebDVD ActiveX Control.
if (
  # Vista / Windows Server 2008
  #
  # empty

  # Windows 2003
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x86", file:"Mswebdvd.dll", version:"6.5.3790.4564", dir:"\System32") ||

  # Windows XP
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Mswebdvd.dll", version:"6.5.2600.5848", dir:"\System32") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Mswebdvd.dll", version:"6.5.2600.3603", dir:"\System32")

  # Windows 2000
  #
  # empty
)
{
  set_kb_item(name:"SMB/Missing/MS09-037", value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end(); 
  exit(0);
}


# Outlook Express.
programfiles = hotfix_get_programfilesdir();
if  (!programfiles)
{
  hotfix_check_fversion_end(); 
  exit(1, "Can't determine location of Program Files.");
}
if (
  # Vista / Windows Server 2008
  #
  # empty

  # Windows 2003
  hotfix_is_vulnerable(os:"5.2", sp:2,             file:"Msoe.dll", version:"6.0.3790.4548",                         dir:"\Outlook Express", path:programfiles) ||

  # Windows XP
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Msoe.dll", version:"6.0.2900.5843",                         dir:"\Outlook Express", path:programfiles) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x64", file:"Msoe.dll", version:"6.0.3790.4548",                         dir:"\Outlook Express", path:programfiles) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Msoe.dll", version:"6.0.2900.3598",                         dir:"\Outlook Express", path:programfiles) ||

  # Windows 2000
  hotfix_is_vulnerable(os:"5.0",                   file:"Msoe.dll", version:"6.0.2800.1983",  min_version:"6.0.0.0", dir:"\Outlook Express", path:programfiles) ||
  hotfix_is_vulnerable(os:"5.0",                   file:"Msoe.dll", version:"5.50.5003.1000",                        dir:"\Outlook Express", path:programfiles)
)
{
  set_kb_item(name:"SMB/Missing/MS09-037", value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end(); 
  exit(0);
}


# DHTML Editing Component ActiveX control/
commonfiles = hotfix_get_officecommonfilesdir();
if  (!commonfiles)
{
  hotfix_check_fversion_end(); 
  exit(1, "Can't determine location of Common Files.");
}
if (
  # Vista / Windows Server 2008
  #
  # empty

  # Windows 2003
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Dhtmled.ocx", version:"6.1.0.9247", dir:"\Microsoft Shared\Triedit", path:commonfiles) ||

  # Windows XP
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Dhtmled.ocx", version:"6.1.0.9247", dir:"\Microsoft Shared\Triedit", path:commonfiles) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, file:"Dhtmled.ocx", version:"6.1.0.9247", dir:"\Microsoft Shared\Triedit", path:commonfiles) ||

  # Windows 2000
  hotfix_is_vulnerable(os:"5.0",       file:"Dhtmled.ocx", version:"6.1.0.9234", dir:"\Microsoft Shared\Triedit", path:commonfiles)
)
{
  set_kb_item(name:"SMB/Missing/MS09-037", value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end(); 
  exit(0);
}


hotfix_check_fversion_end(); 
exit(0, "The host is not affected.");
