#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(35630);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2009-0075", "CVE-2009-0076");
  script_bugtraq_id(33627, 33628);
  script_xref(name:"OSVDB", value:"51839");
  script_xref(name:"OSVDB", value:"51840");

  script_name(english: "MS09-002: Cumulative Security Update for Internet Explorer (961260)");
  script_summary(english:"Determines the presence of update 961260");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web
client." );
 script_set_attribute(attribute:"description", value:
"The remote host is missing IE Security Update 961260. 

The remote version of IE is affected by two memory corruption
vulnerabilities that may allow an attacker to execute arbitrary code
on the remote host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista
and 2008 :

http://www.microsoft.com/technet/security/Bulletin/MS09-002.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
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


if (hotfix_check_sp(xp:4, win2003:3, vista:2) <= 0) exit(0);

if (is_accessible_share())
{
  if (
    # Vista / Windows 2008
    hotfix_is_vulnerable(os:"6.0", file:"Mshtml.dll", version:"8.0.6001.22352", min_version:"8.0.6001.20000", dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0", file:"Mshtml.dll", version:"8.0.6001.18259", min_version:"8.0.0.0", dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0", sp:1, file:"Mshtml.dll", version:"7.0.6001.22355", min_version:"7.0.6001.20000", dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0", sp:1, file:"Mshtml.dll", version:"7.0.6001.18203", min_version:"7.0.0.0", dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0", sp:0, file:"Mshtml.dll", version:"7.0.6000.20996", min_version:"7.0.6000.20000", dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0", sp:0, file:"Mshtml.dll", version:"7.0.6000.16809", min_version:"7.0.0.0", dir:"\system32") ||

    # Windows 2003
    hotfix_is_vulnerable(os:"5.2", file:"Mshtml.dll", version:"8.0.6001.22352", min_version:"8.0.6001.20000", dir:"\system32") ||
    hotfix_is_vulnerable(os:"5.2", file:"Mshtml.dll", version:"8.0.6001.18259", min_version:"8.0.6001.0", dir:"\system32") ||
    hotfix_is_vulnerable(os:"5.2", file:"Mshtml.dll", version:"7.0.6000.20996", min_version:"7.0.6000.20000", dir:"\system32") ||
    hotfix_is_vulnerable(os:"5.2", file:"Mshtml.dll", version:"7.0.6000.16809", min_version:"7.0.0.0", dir:"\system32") ||

    # Windows XP
    hotfix_is_vulnerable(os:"5.1", file:"Mshtml.dll", version:"8.0.6001.22352", min_version:"8.0.6001.20000", dir:"\system32") ||
    hotfix_is_vulnerable(os:"5.1", file:"Mshtml.dll", version:"8.0.6001.18259", min_version:"8.0.0.0", dir:"\system32") ||
    hotfix_is_vulnerable(os:"5.1", file:"Mshtml.dll", version:"7.0.6000.20996", min_version:"7.0.6000.20000", dir:"\system32") ||
    hotfix_is_vulnerable(os:"5.1", file:"Mshtml.dll", version:"7.0.6000.16809", min_version:"7.0.0.0", dir:"\system32")
  ) {
 set_kb_item(name:"SMB/Missing/MS09-002", value:TRUE);
 hotfix_security_hole();
 }
 
  hotfix_check_fversion_end(); 
  exit(0);
}
