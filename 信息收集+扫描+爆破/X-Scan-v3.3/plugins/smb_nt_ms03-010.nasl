#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11485);
 script_version ("$Revision: 1.23 $");

 script_cve_id("CVE-2002-1561");
 script_bugtraq_id(6005);
 script_xref(name:"IAVA", value:"2003-t-0008");
 script_xref(name:"OSVDB", value:"13414");
 
 script_name(english:"MS03-010: Flaw in RPC Endpoint Mapper Could Allow Denial of Service Attacks (331953)");
 script_summary(english:"Checks SP version");
 
 script_set_attribute(
  attribute:"synopsis",
  value:"It is possible to disable the remote RPC service."
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "A flaw exists in the RPC endpoint mapper, which can be used by an\n",
   "attacker to disable it remotely."
  )
 );
 script_set_attribute(
  attribute:"solution", 
  value:string(
   "Microsoft has released a set of patches for the Windows 2000 and XP :\n",
   "\n",
   "http://www.microsoft.com/technet/security/bulletin/ms03-010.mspx\n",
   "\n",
   "There is no patch for NT4.  Microsoft strongly recommends that\n",
   "customers still using Windows NT 4.0 protect those systems by placing\n",
   "them behind a firewall that is filtering traffic on port 135."
  )
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P"
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

if ( hotfix_check_sp(nt:7, win2k:4, xp:2) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", sp:1, file:"Rpcrt4.dll", version:"5.1.2600.1140", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"Rpcrt4.dll", version:"5.1.2600.105", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Rpcrt4.dll", version:"5.0.2195.6106", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"Rpcrt4.dll", version:"5.0.0.0", dir:"\system32") )
   security_warning (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"331953") > 0 && 
          hotfix_missing(name:"824146") > 0 && 
          hotfix_missing(name:"873333") > 0 && 
          hotfix_missing(name:"828741") > 0 &&
          hotfix_missing(name:"902400") > 0 &&
	  !((hotfix_check_sp (win2k:6) > 0) && ( hotfix_missing(name:"913580") <= 0 ) ) )
  hotfix_security_warning();
