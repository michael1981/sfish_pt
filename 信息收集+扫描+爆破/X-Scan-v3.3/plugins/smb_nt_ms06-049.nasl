#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(22191);
 script_version("$Revision: 1.12 $");

 script_cve_id("CVE-2006-3444");
 script_bugtraq_id(19388);
 script_xref(name:"OSVDB", value:"27848");

 name["english"] = "MS06-049: Vulnerability in Windows Kernel Could Result in Elevation of Privilege (920958)";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"A local user can elevate his privileges on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the Windows kernel that may
allow a local user to elevate his privileges or to crash it (therefore
causing a denial of service)." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000 :

http://www.microsoft.com/technet/security/bulletin/ms06-049.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
 summary["english"] = "Determines if hotfix 920958 has been installed";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

if ( hotfix_check_sp(win2k:6) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.0", file:"Ntkrnlpa.exe", version:"5.0.2195.7111", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS06-049", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"920958") > 0 &&
          hotfix_missing(name:"931784") > 0  )
{
 {
 set_kb_item(name:"SMB/Missing/MS06-049", value:TRUE);
 hotfix_security_hole();
 }
}

