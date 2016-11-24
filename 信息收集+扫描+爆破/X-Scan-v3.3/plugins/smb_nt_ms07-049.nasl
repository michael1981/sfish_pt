#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(25902);
 script_version("$Revision: 1.7 $");

 script_cve_id("CVE-2007-0948");
 script_bugtraq_id(25298);
 script_xref(name:"OSVDB", value:"36389");

 name["english"] = "MS07-049: Vulnerability in Virtual PC and Virtual Server Could Allow Elevation of Privilege (937986)";


 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"A user can elevate his privileges on the virtual system." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Virtual PC or Virtual Server
which is vulerable to a heap overflow which may allow arbitrary code
to be run. 

An attacker may use this to execute arbitrary code on the host
operating system or others guests. 

To succeed, the attacker needs administrative privileges on the guest
operating system." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Virtual PC 2004 and
Virtual Server 2005 :

http://www.microsoft.com/technet/security/bulletin/ms07-049.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 
 summary["english"] = "Determines the version of Virtual PC/Server";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/WindowsVersion");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

if ( ! get_kb_item("SMB/WindowsVersion") ) exit(1);
if ( ! is_accessible_share() ) exit(1);

path = hotfix_get_programfilesdir();
if ( ! path ) exit(1);

if ( ( hotfix_check_fversion(path:path, file:"Microsoft Virtual PC\Virtual PC.exe", version:"5.3.0.583") == HCF_OLDER ) ||
     ( hotfix_check_fversion(path:path, file:"Microsoft Virtual PC\Virtual PC.exe", version:"5.3.582.44", min_version:"5.3.582.0") == HCF_OLDER ) ||
     ( hotfix_check_fversion(path:path, file:"Microsoft Virtual Server\vssrvc.exe", version:"1.1.465.15") == HCF_OLDER ) ||
     ( hotfix_check_fversion(path:path, file:"Microsoft Virtual Server\vssrvc.exe", version:"1.1.465.106", min_version:"1.1.465.100") == HCF_OLDER ) ||
     ( hotfix_check_fversion(path:path, file:"Microsoft Virtual Server\vssrvc.exe", version:"1.1.465.356", min_version:"1.1.465.300") == HCF_OLDER ) )
 {
 set_kb_item(name:"SMB/Missing/MS07-049", value:TRUE);
 hotfix_security_hole();
 }
 
hotfix_check_fversion_end(); 
