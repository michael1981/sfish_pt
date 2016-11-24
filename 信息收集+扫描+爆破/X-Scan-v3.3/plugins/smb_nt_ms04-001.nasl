#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11992);
 script_version("$Revision: 1.18 $");

 script_cve_id("CVE-2003-0819");
 script_bugtraq_id(9408);
 script_xref(name:"IAVA", value:"2004-B-0002");
 script_xref(name:"OSVDB", value:"11712");
 
 name["english"] = "MS04-001: Vulnerability in Microsoft ISA Server 2000 H.323 Filter(816458)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host." );
 script_set_attribute(attribute:"description", value:
"A buffer overflow vulnerability in the H.323 filter of the Microsoft
ISA Server 2000 allows an attacker to execute arbitrary code on the
remote host.  An attacker can exploit this vulnerability by sending a
specially crafted packet to the remote ISA Server." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for ISA Server Gold and SP1 :

http://www.microsoft.com/technet/security/bulletin/ms04-001.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();


 summary["english"] = "Checks for hotfix Q816458";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/registry_full_access","SMB/WindowsVersion");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

port = get_kb_item("SMB/transport");
if(!port)port = 139;

access = get_kb_item("SMB/registry_full_access");
if(!access)exit(0);

path = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc");
if (!path) exit(0, "ISA Server does not appear to be installed.");

if (is_accessible_share ())
{
 if ( hotfix_check_fversion(path:path, file:"H323asn1.dll", version:"3.0.1200.291") == HCF_OLDER )
 {
  set_kb_item(name:"SMB/Missing/MS04-001", value:TRUE);
  hotfix_security_hole();
 }
 hotfix_check_fversion_end();
}
else 
{
 #superseded by SP2
 fix = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc/Hotfixes/SP1/365");
 if(fix) exit(0);

 fix = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc/Hotfixes/SP1/291");
 if(!fix)
 {
  set_kb_item(name:"SMB/Missing/MS04-001", value:TRUE);
  hotfix_security_hole();
 }
}
