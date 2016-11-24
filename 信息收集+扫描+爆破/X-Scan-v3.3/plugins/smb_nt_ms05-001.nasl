#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(16123);
 script_version("$Revision: 1.14 $");

 script_cve_id("CVE-2004-1043");
 script_xref(name:"IAVA", value:"2005-A-0002");
 script_xref(name:"OSVDB", value:"12840");

 script_name(english:"MS05-001: HTML Help Code Execution (890175)");
 script_summary(english:"Checks version of Hhctrl.ocx");

 script_set_attribute(
  attribute:"synopsis",
  value:string(
   "Arbitrary code can be executed on the remote host through the web\n",
   "client."
  )
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The remote host contains a version of the HTML Help ActiveX control\n",
   "that may allow an attacker to execute arbitrary code on the remote\n",
   "host by constructing a malicious web page and entice a victim to visit\n",
   "this web page."
  )
 );
 script_set_attribute(
  attribute:"solution", 
  value:string(
   "Microsoft has released a set of patches for Windows NT, 2000, XP and\n",
   "2003 :\n",
   "\n",
   "http://www.microsoft.com/technet/security/bulletin/ms05-001.mspx"
  )
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
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

if ( hotfix_check_sp(nt:7, xp:3, win2k:5, win2003:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Hhctrl.ocx", version:"5.2.3790.233", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Hhctrl.ocx", version:"5.2.3790.233", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Hhctrl.ocx", version:"5.2.3790.1280", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Hhctrl.ocx", version:"5.2.3790.233", dir:"\system32") || 
      hotfix_is_vulnerable (os:"4.0", file:"Hhctrl.ocx", version:"5.2.3790.233", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS05-001", value:TRUE);
 security_hole(get_kb_item("SMB/transport"));
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else
{
 if ( hotfix_missing(name:"890175") > 0 && 
      hotfix_missing(name:"922616") > 0 &&
      hotfix_missing(name:"928843") > 0 &&
      hotfix_missing(name:"896358") > 0 )
 {
 set_kb_item(name:"SMB/Missing/MS05-001", value:TRUE);
 hotfix_security_hole();
 }
}
