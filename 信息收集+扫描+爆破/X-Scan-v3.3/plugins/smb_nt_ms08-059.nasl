#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(34404);
 script_version("$Revision: 1.6 $");

 script_cve_id("CVE-2008-3466");
 script_bugtraq_id(31620);
 script_xref(name:"OSVDB", value:"49068");

 name["english"] = "MS08-059: Microsoft Host Integration Server (HIS) SNA RPC Request Remote Overflow (956695)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Host
Integration Server (HIS)." );
 script_set_attribute(attribute:"description", value:
"The remote host has HIS (Host Integration Server) installed.  The
remote version of this product contains a code execution vulnerability
in its RPC interface. 

An attacker could exploit this flaw to execute arbitrary code on the
remote host by making rogue RPC queries." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for HIS 2000, 2003 and 2006 :

http://www.microsoft.com/technet/security/Bulletin/MS08-059.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Determines the presence of update 956695";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
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


if (is_accessible_share())
{
 programfiles = hotfix_get_programfilesdir();
 if ( 
      hotfix_check_fversion(file:"Rpcdetct.dll", version:"5.0.1.798", path:programfiles + "\Host Integration Server\System") == HCF_OLDER ||   # 2000
      hotfix_check_fversion(file:"Rpcdetct.dll", version:"6.0.2430.0", min_version:"6.0.2400.0", path:programfiles + "\Microsoft Host Integration Server\System") == HCF_OLDER || # 2004 SP1 server
      hotfix_check_fversion(file:"Hisservicelib.dll", version:"6.0.2430.0", min_version:"6.0.2400.0", path:programfiles + "\Microsoft Host Integration Server\System") == HCF_OLDER || # 2004 SP1 client
      hotfix_check_fversion(file:"Hisservicelib.dll", version:"6.0.2119.0", min_version:"6.0.0.0", path:programfiles + "\Microsoft Host Integration Server\System") == HCF_OLDER || # 2004 client
      hotfix_check_fversion(file:"Rpcdetct.dll", version:"7.0.2900.0", min_version:"7.0.0.0", path:programfiles + "\Microsoft Host Integration Server 2006\System")  == HCF_OLDER # 2006
     )
 {
 set_kb_item(name:"SMB/Missing/MS08-059", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
