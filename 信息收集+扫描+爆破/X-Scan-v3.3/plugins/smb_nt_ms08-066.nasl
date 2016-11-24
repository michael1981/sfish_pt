#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(34411);
 script_version("$Revision: 1.6 $");

 script_cve_id("CVE-2008-3464");
 script_bugtraq_id(31673);
 script_xref(name:"OSVDB", value:"49061");

 name["english"] = "MS08-066: Microsoft Windows Ancillary Function Driver (afd.sys) Local Privilege Escalation (956803)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"A local user can elevate his privileges on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of Windows which is vulnerable
to a security flaw which may allow a local user to elevate his privileges
or to crash it (therefore causing a denial of service)." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms08-066.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );



script_end_attributes();

 
 summary["english"] = "Determines the presence of update 956803";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");


if ( hotfix_check_sp(xp:4, win2003:3) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( 
      hotfix_is_vulnerable (os:"5.2", sp:2, file:"Afd.sys", version:"5.2.3790.4355", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Afd.sys", version:"5.2.3790.3192", dir:"\system32\drivers") ||

      hotfix_is_vulnerable (os:"5.1", sp:3, file:"Afd.sys", version:"5.1.2600.5657", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Afd.sys", version:"5.1.2600.3427", dir:"\system32\drivers")  )
 {
 set_kb_item(name:"SMB/Missing/MS08-066", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}

