#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(35631);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2009-0098", "CVE-2009-0099");
  script_bugtraq_id(33134, 33136);
  script_xref(name:"OSVDB", value:"51837");
  script_xref(name:"OSVDB", value:"51838");

  script_name(english: "MS09-003: Vulnerabilities in Microsoft Exchange Could Allow Remote Code Execution (959239)");
  script_summary(english:"Determines the version of Exchange");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the email
server." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Exchange that is
affected by a memory corruption vulnerability that could lead to
remote code execution when processing a specially crafted TNEF message
as well as a denial of service vulnerability when processing a
specially crafted MAPI command that could cause the Microsoft Exchange
System Attendant service and other services that use the EMSMDB32
provider to stop responding." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Exchange 2000, 2003, and
2007 :

http://www.microsoft.com/technet/security/Bulletin/MS09-003.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/Exchange/Version");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


version = get_kb_item("SMB/Exchange/Version");
if (!version) exit(0);


# 2000
if (version == 60)
{
  sp = get_kb_item ("SMB/Exchange/SP");
  rootfile = get_kb_item("SMB/Exchange/Path");
  if (!rootfile || (sp && sp > 4)) exit(0);

  rootfile = rootfile + "\bin";
  if (hotfix_check_fversion(path:rootfile, file:"Emsmdb32.dll", version:"6.0.6620.9") == HCF_OLDER) {
 set_kb_item(name:"SMB/Missing/MS09-003", value:TRUE);
 hotfix_security_hole();
 }

  hotfix_check_fversion_end();
}
# 2003
else if (version == 65)
{
  sp = get_kb_item ("SMB/Exchange/SP");
  rootfile = hotfix_get_commonfilesdir() + "\Microsoft Shared\CDO";
  if (!rootfile || (sp && sp > 2)) exit(0);

  if (hotfix_check_fversion(path:rootfile, file:"Cdoex.dll", version:"6.5.7654.12") == HCF_OLDER) {
 set_kb_item(name:"SMB/Missing/MS09-003", value:TRUE);
 hotfix_security_hole();
 }

  hotfix_check_fversion_end();
}
# 2007
else if (version == 80)
{
  sp = get_kb_item ("SMB/Exchange/SP");
  rootfile = hotfix_get_commonfilesdir() + "\Microsoft Shared\CDO";
  if (!rootfile || (sp && sp > 1)) exit(0);

  if (
    hotfix_check_fversion(path:rootfile, file:"Cdoex.dll", version:"8.1.338.0", min_version:"8.1.0.0") == HCF_OLDER ||
    hotfix_check_fversion(path:rootfile, file:"Cdoex.dll", version:"8.0.834.0") == HCF_OLDER 
  ) {
 set_kb_item(name:"SMB/Missing/MS09-003", value:TRUE);
 hotfix_security_hole();
 }

  hotfix_check_fversion_end();
}
