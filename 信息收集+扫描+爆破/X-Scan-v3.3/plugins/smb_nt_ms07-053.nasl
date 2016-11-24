#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(26018);
 script_version("$Revision: 1.8 $");

 script_cve_id("CVE-2007-3036");
 script_bugtraq_id(25620);
 script_xref(name:"OSVDB", value:"36935");

 name["english"] = "MS07-053: Vulnerability in Windows Services for UNIX Could Allow Elevation of Privilege (939778)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"A local user can elevate his privileges." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of the Windows Services for UNIX
which is vulnerable to a local privileges elevation due to a flaw in
different setuid binary files.

An attacker may use this to elevate his privileges on this host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Services fo UNIX
3.0, 3.5 and 4.0 :

http://www.microsoft.com/technet/security/bulletin/ms07-053.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 
 summary["english"] = "Determines the version of Services for UNIX";

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


path = hotfix_get_systemroot();
if ( ! path ) exit(1);

if ( ( hotfix_check_fversion(path:path, file:"system32\posix.exe", version:"7.0.1701.46", min_version:"7.0.0.0") == HCF_OLDER ) ||
     ( hotfix_check_fversion(path:path, file:"system32\posix.exe", version:"8.0.1969.58", min_version:"8.0.0.0") == HCF_OLDER ) ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"posix.exe", version:"6.0.6000.16543", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"posix.exe", version:"6.0.6000.20660", min_version:"6.0.6000.20000", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"posix.exe", version:"9.0.3790.2983", min_version:"9.0.0.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:2, file:"posix.exe", version:"9.0.3790.4125", min_version:"9.0.0.0", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS07-053", value:TRUE);
 hotfix_security_warning();
 }
 
hotfix_check_fversion_end(); 
