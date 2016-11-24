#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(16125);
 script_version("$Revision: 1.15 $");

 script_cve_id("CVE-2004-0897");
 script_bugtraq_id(12228);
 script_xref(name:"IAVA", value:"2005-t-0001");
 script_xref(name:"OSVDB", value:"12832");

 script_name(english:"MS05-003: Indexing Service Code Execution (871250)");
 script_summary(english:"Checks version of Query.dll / Ciodm.dll");
 
 script_set_attribute(
  attribute:"synopsis",
  value:"Arbitrary code can be executed on the remote host."
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The remote host contains a version of the Indexing Service that may\n",
   "allow an attacker to execute arbitrary code on the remote host by\n",
   "constructing a malicious query."
  )
 );
 script_set_attribute(
  attribute:"solution", 
  value:string(
   "Microsoft has released a set of patches for Windows NT, 2000, XP and\n",
   "2003 :\n",
   "\n",
   "http://www.microsoft.com/technet/security/bulletin/ms05-003.mspx"
  )
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C"
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

if ( hotfix_check_sp(xp:2, win2k:5, win2003:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Query.dll", version:"5.2.3790.220", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Query.dll", version:"5.1.2600.1596", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Ciodm.dll", version:"5.0.2195.6981", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS05-003", value:TRUE);
 security_hole(get_kb_item("SMB/transport"));
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else
{
 if ((hotfix_check_sp (xp:2, win2k:5) > 0) &&
     (hotfix_missing(name:"920685") <= 0 ))
   exit(0);

 if ( hotfix_missing(name:"871250") > 0 )
 {
 set_kb_item(name:"SMB/Missing/MS05-003", value:TRUE);
 hotfix_security_hole();
 }
}
