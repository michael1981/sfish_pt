#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(15962);
 script_version("$Revision: 1.14 $");

 script_cve_id("CVE-2004-0567", "CVE-2004-1080");
 script_bugtraq_id(11763, 11922);
 script_xref(name:"IAVA", value:"2004-b-0016");
 script_xref(name:"IAVA", value:"2004-t-0039");
 script_xref(name:"OSVDB", value:"12370");
 script_xref(name:"OSVDB", value:"12378");

 script_name(english:"MS04-045: WINS Code Execution (870763)");
 script_summary(english:"Checks version of Wins.exe.");
 
 script_set_attribute(
  attribute:"synopsis",
  value:string(
   "Arbitrary code can be executed on the remote host via the WINS\n",
   "service."
  )
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The remote Windows Internet Naming Service (WINS) server is prone to a\n",
   "heap overflow attack that could allow an attacker to execute arbitrary\n",
   "code on this host.\n",
   "\n",
   "To exploit this flaw, an attacker would need to send a specially crafted\n",
   "packet to port 42 of the remote host."
  )
 );
 script_set_attribute(
  attribute:"solution", 
  value:string(
   "Microsoft has released a set of patches for Windows NT, 2000 and \n",
   "2003 :\n",
   "\n",
   "http://www.microsoft.com/technet/security/bulletin/ms04-045.mspx"
  )
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
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


if ( hotfix_check_nt_server() <= 0 ) exit(0);
if ( hotfix_check_wins_installed() <= 0 ) exit(0);
if ( hotfix_check_sp(nt:7, win2k:5, win2003:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Wins.exe", version:"5.2.3790.239", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Wins.exe", version:"5.0.2195.7005", dir:"\system32") || 
      hotfix_is_vulnerable (os:"4.0", file:"Wins.exe", version:"4.0.1381.7329", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS04-045", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"870763") > 0 )
	 {
 set_kb_item(name:"SMB/Missing/MS04-045", value:TRUE);
 hotfix_security_hole();
 }
