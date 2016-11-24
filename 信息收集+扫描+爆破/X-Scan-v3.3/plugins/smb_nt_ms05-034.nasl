#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if(description)
{
 script_id(18487);
 script_version("$Revision: 1.17 $");

 script_cve_id("CVE-2005-1215", "CVE-2005-1216", "CVE-2005-1907");
 script_bugtraq_id(13846, 13954, 13955, 13956);
 script_xref(name:"IAVA", value:"2005-B-0013");
 script_xref(name:"OSVDB", value:"17031");
 script_xref(name:"OSVDB", value:"17311");
 script_xref(name:"OSVDB", value:"17312");
 script_xref(name:"OSVDB", value:"17342");
 
 name["english"] = "MS05-034: Cumulative Update for ISA Server 2000 (899753)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"A user can elevate his privileges." );
 script_set_attribute(attribute:"description", value:
"The remote host is missing a cumulative update for ISA Server 2000
that fixes several security flaws that may allow an attacker to
elevate his privileges." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for ISA Server 2000 :

http://www.microsoft.com/technet/security/bulletin/ms05-034.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P" );
script_end_attributes();

 
 summary["english"] = "Checks for hotfix 899753";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/registry_full_access","SMB/WindowsVersion");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

if ( !get_kb_item("SMB/registry_full_access") ) exit(0);

path = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc");
if (!path) exit(0, "ISA Server does not appear to be installed.");

if (is_accessible_share ())
{
 if ( hotfix_check_fversion(path:path, file:"wspsrv.exe", version:"3.0.1200.430") == HCF_OLDER )
 {
  set_kb_item(name:"SMB/Missing/MS05-034", value:TRUE);
  hotfix_security_warning();
 }
 hotfix_check_fversion_end();
}
else
{
 fix = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc/Hotfixes/SP1/430");
 if(!fix)
 {
  set_kb_item(name:"SMB/Missing/MS05-034", value:TRUE);
  hotfix_security_warning();
 }
}
