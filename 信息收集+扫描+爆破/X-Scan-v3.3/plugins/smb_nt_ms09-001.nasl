#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(35361);
 script_version("$Revision: 1.6 $");

 script_cve_id("CVE-2008-4834", "CVE-2008-4835", "CVE-2008-4114");
 script_bugtraq_id(31179, 33121, 33122);
 script_xref(name:"OSVDB", value:"48153");
 script_xref(name:"OSVDB", value:"52691");
 script_xref(name:"OSVDB", value:"52692");

 script_name(english:"MS09-001: Vulnerabilities in SMB Could Allow Remote Code Execution (958687)");
 script_summary(english:"Determines the presence of update 958687");

 script_set_attribute(
  attribute:"synopsis",
  value:"It is possible to crash the remote host due to a flaw in SMB."
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The remote host is affected by a memory corruption vulnerability in\n",
   "SMB that may allow an attacker to execute arbitrary code or perform a\n",
   "denial of service against the remote host."
  )
 );
 script_set_attribute(
  attribute:"solution", 
  value:string(
   "Microsoft has released a set of patches for Windows 2000, XP, 2003,\n",
   "Vista and 2008 :\n",
   "\n",
   "http://www.microsoft.com/technet/security/bulletin/ms09-001.mspx"
  )
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
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


if ( hotfix_check_sp(xp:4, win2003:3, win2k:6, vista:2) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( 
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"Srv.sys", version:"6.0.6000.16789", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"Srv.sys", version:"6.0.6000.20976", min_version:"6.0.6000.20000", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"6.0", sp:1, file:"Srv.sys", version:"6.0.6001.18185", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"6.0", sp:1, file:"Srv.sys", version:"6.0.6001.22331", min_version:"6.0.6001.20000", dir:"\system32\drivers") ||

      hotfix_is_vulnerable (os:"5.2", sp:2, file:"Srv.sys", version:"5.2.3790.4425", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Srv.sys", version:"5.2.3790.3260", dir:"\system32\drivers") ||

      hotfix_is_vulnerable (os:"5.1", sp:3, file:"Srv.sys", version:"5.1.2600.5725", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Srv.sys", version:"5.1.2600.3491", dir:"\system32\drivers") ||

      hotfix_is_vulnerable (os:"5.0", file:"Srv.sys", version:"5.0.2195.7222", dir:"\system32\drivers") )
   hotfix_security_hole();
 
 hotfix_check_fversion_end(); 
 exit (0);
}

