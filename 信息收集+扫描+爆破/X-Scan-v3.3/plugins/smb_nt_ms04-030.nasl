#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(15455);
 script_version("$Revision: 1.14 $");

 script_cve_id("CVE-2003-0718");
 script_bugtraq_id(11384);
 script_xref(name:"IAVA", value:"2004-t-0033");
 script_xref(name:"OSVDB", value:"10688");

 name["english"] = "MS04-030: WebDAV XML Message Handler Denial of Service (824151)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to crash the remote web server." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Windows and IIS that is
vulnerable to a remote denial of service attack through the WebDAV XML
Message Handler. 

An attacker may exploit this flaw to prevent the remote web server
from working properly." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 
2003 :

http://www.microsoft.com/technet/security/bulletin/ms04-030.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C" );
script_end_attributes();

 
 summary["english"] = "Determines if hotfix 824151 has been installed";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
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

if ( hotfix_check_iis_installed() <= 0 ) exit(0);
if ( hotfix_check_sp(win2k:5, xp:2, win2003:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Msxml3.dll", version:"8.50.2162.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Msxml3.dll", version:"8.50.2162.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"Msxml3.dll", version:"8.50.2162.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Msxml3.dll", version:"8.50.2162.0", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS04-030", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"824151") > 0  &&
	  hotfix_missing(name:"924191") > 0  &&
          hotfix_missing(name:"928088") > 0 &&
          hotfix_missing(name:"936227") > 0 &&
          hotfix_missing(name:"936021") > 0)
	 {
 set_kb_item(name:"SMB/Missing/MS04-030", value:TRUE);
 hotfix_security_hole();
 }

