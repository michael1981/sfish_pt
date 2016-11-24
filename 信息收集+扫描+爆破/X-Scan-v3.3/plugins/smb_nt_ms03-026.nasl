#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11790);
 script_version("$Revision: 1.32 $");

 script_cve_id(
  "CVE-2003-0352", 
  "CVE-2003-0715", 
  "CVE-2003-0528", 
  "CVE-2003-0605"
 );
 script_bugtraq_id(8205, 8458, 8460);
 script_xref(name:"IAVA", value:"2003-A-0011");
 script_xref(name:"OSVDB", value:"2100");
 script_xref(name:"OSVDB", value:"2535");
 script_xref(name:"OSVDB", value:"11460");
 script_xref(name:"OSVDB", value:"11797");
 
 name["english"] = "MS03-026 / MS03-039: Buffer Overrun In RPCSS Service Could Allow Code Execution (823980 / 824146)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Windows affected by several
vulnerabilities in its RPC interface and RPCSS Service, which may
allow an attacker to execute arbitrary code and gain SYSTEM
privileges." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows NT, 2000, XP and
2003 :

http://www.microsoft.com/technet/security/bulletin/ms03-026.mspx
http://www.microsoft.com/technet/security/bulletin/ms03-039.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 summary["english"] = "Checks for hotfix Q824146";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
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

if ( get_kb_item("SMB/KB824146") ) exit(0);

if ( hotfix_check_sp(nt:7, win2k:5, xp:2, win2003:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Rpcrt4.dll", version:"5.2.3790.59", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Rpcrt4.dll", version:"5.1.2600.1230", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"Rpcrt4.dll", version:"5.1.2600.109", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Rpcrt4.dll", version:"5.0.2195.6753", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"Rpcrt4.dll", version:"4.0.1381.7219", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"Rpcrt4.dll", version:"4.0.1381.33474", min_version:"4.0.1381.33000", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS03-039", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"824146") > 0 && 
          hotfix_missing(name:"828741") > 0 &&
          hotfix_missing(name:"873333") > 0 &&
          hotfix_missing(name:"902400") > 0 &&
	  !((hotfix_check_sp (win2k:6) > 0) && ( hotfix_missing(name:"913580") <= 0 ) ) )
	 {
 set_kb_item(name:"SMB/Missing/MS03-039", value:TRUE);
 hotfix_security_hole();
 }
