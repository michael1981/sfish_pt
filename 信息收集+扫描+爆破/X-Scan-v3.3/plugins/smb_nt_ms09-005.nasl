#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(35633);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2009-0095", "CVE-2009-0096", "CVE-2009-0097");
  script_bugtraq_id(33659, 33660, 33661);
  script_xref(name:"OSVDB", value:"51834");
  script_xref(name:"OSVDB", value:"51835");
  script_xref(name:"OSVDB", value:"51836");

  script_name(english: "MS09-005: Vulnerabilities in Microsoft Office Visio Could Allow Remote Code Execution (957634)");
  script_summary(english:"Determines the presence of update 957634");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Visio." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of Microsoft Visio that is affected
by memory corruption and memory validation vulnerabilities triggered
when parsing specially crafted Visio files which could be be abused to
execute arbitrary code on the remote host. 

To exploit this vulnerability, an attacker would need to spend a
specially crafted Visio document to a user on the remote host and
trick him to open it." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft Visio 2002, 2003
and 2007 :

http://www.microsoft.com/technet/security/Bulletin/MS09-005.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/Office/Visio", "SMB/Office/VisioPath");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");


version = get_kb_item("SMB/Office/Visio");
if (isnull(version)) exit(0);
if ("12.0" >!< version && "11.0" >!< version && "10.0" >!< version) exit(0);


path = get_kb_item("SMB/Office/VisioPath");
if (isnull(path)) exit(0);


if (is_accessible_share())
{
  vuln = 0;

  if ("12.0" >< version)  # Visio 2007
  {
   if (hotfix_check_fversion(path:path, file:"Vislib.dll", version:"12.0.6336.5001") == HCF_OLDER) vuln++;
  }
  else if ("11.0" >< version)  # Visio 2003
  {
   if (hotfix_check_fversion(path:path, file:"Visio11\Vislib.dll", version:"11.0.8223.0") == HCF_OLDER) vuln++;
  }
  else if ("10.0" >< version)  # Visio 2002
  {
   if ( hotfix_check_fversion(path:path, file:"Visio10\Vislib.dll", version:"10.0.6885.4") == HCF_OLDER) vuln++;
  }

  if (vuln) {
 set_kb_item(name:"SMB/Missing/MS09-005", value:TRUE);
 hotfix_security_hole();
 }

  hotfix_check_fversion_end();
}
