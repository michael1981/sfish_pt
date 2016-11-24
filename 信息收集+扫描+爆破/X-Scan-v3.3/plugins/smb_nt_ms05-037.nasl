#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(18682);
 script_version("$Revision: 1.16 $");

 script_cve_id("CVE-2005-2087");
 script_bugtraq_id(14087);
 script_xref(name:"IAVA", value:"2005-B-0016");
 script_xref(name:"OSVDB", value:"17680");
 
 name["english"] = "MS05-037: Vulnerability in JView Profiler Could Allow Code Execution (903235)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web
client." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the JView Profiler module which
is vulnerable to a security flaw that may allow an attacker to execute
arbitrary code on the remote host by constructing a malicious web page
and enticing a victim to visit this web page." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 
2003 :

http://www.microsoft.com/technet/security/bulletin/ms05-037.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Determines the presence of update 903235";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl","smb_nt_ms05-038.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


if ( hotfix_check_sp(xp:3, win2003:2, win2k:6) <= 0 ) exit(0);


if ( hotfix_ie_gt(7) != 0 ) exit(0);
if ( hotfix_missing(name:"896727") <= 0 ) exit(0); 
if ( hotfix_missing(name:"896688") <= 0 ) exit(0); 
if ( hotfix_missing(name:"905915") <= 0 ) exit(0); 
if ( hotfix_missing(name:"903235") > 0 )
{
 if (get_kb_item ("SMB/Registry/HKLM/SOFTWARE/Microsoft/Internet Explorer/ActiveX Compatibility/{03D9F3F2-B0E3-11D2-B081-006008039BF0}"))
   exit (0);

 minorversion = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Internet Settings/MinorVersion");
 if ( "903235" >!< minorversion ) {
 set_kb_item(name:"SMB/Missing/MS05-037", value:TRUE);
 hotfix_security_hole();
 }
}
