#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(16124);
 script_version("$Revision: 1.20 $");

 script_cve_id("CVE-2004-1049", "CVE-2004-1305", "CVE-2005-0416");
 script_bugtraq_id(12095, 12233);
 script_xref(name:"IAVA", value:"2005-A-0001");
 script_xref(name:"OSVDB", value:"12623");
 script_xref(name:"OSVDB", value:"12624");
 script_xref(name:"OSVDB", value:"12842");
 script_xref(name:"OSVDB", value:"16430");

 script_name(english:"MS05-002: Cursor and Icon Format Handling Code Execution (891711)");
 script_summary(english:"Checks version of User32.dll");
 
 script_set_attribute(
  attribute:"synopsis",
  value:string(
   "Arbitrary code can be executed on the remote host through the web or\n",
   "email client."
  )
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The remote host contains a version of the Windows kernel that is\n",
   "affected by a security flaw in the way that cursors and icons are\n",
   "handled.  An attacker may be able to execute arbitrary code on the\n",
   "remote host by constructing a malicious web page and entice a victim\n",
   "to visit this web page.  An attacker may send a malicious email to the\n",
   "victim to exploit this flaw too."
  )
 );
 script_set_attribute(
  attribute:"solution", 
  value:string(
   "Microsoft has released a set of patches for Windows NT, 2000, XP and\n",
   "2003 :\n",
   "\n",
   "http://www.microsoft.com/technet/security/bulletin/ms05-002.mspx"
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

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


if ( hotfix_check_sp(nt:7, xp:2, win2k:5, win2003:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"User32.dll", version:"5.2.3790.245", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"User32.dll", version:"5.1.2600.1617", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"User32.dll", version:"5.0.2195.7017", dir:"\system32") || 
      hotfix_is_vulnerable (os:"4.0", file:"User32.dll", version:"4.0.1381.7342", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"User32.dll", version:"4.0.1381.33630", min_version:"4.0.1381.33000", dir:"\system32") )
 {
   hotfix_security_hole();
   set_kb_item(name:"SMB/Missing/MS05-002", value:TRUE);
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else
{
 if ( hotfix_missing(name:"891711") > 0 )
	{
	# Superseded by MS05-18
	if ( hotfix_check_sp(win2k:5, win2003:1, xp:2) > 0 && hotfix_missing(name:"890859") <= 0 ) exit(0);
	# Superseded by MS05-053
        if ( hotfix_check_sp(xp:2) > 0 && hotfix_missing(name:"896424") <= 0  ) exit(0);
	# Superseded by MS07-017
        if ( hotfix_check_sp(win2003:1) > 0 && hotfix_missing(name:"925902") <= 0  ) exit(0);

   	set_kb_item(name:"SMB/Missing/MS05-002", value:TRUE);
	hotfix_security_hole();
	}
}
