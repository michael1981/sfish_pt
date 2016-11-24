#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11433);
 script_version ("$Revision: 1.21 $");

 script_cve_id("CVE-2003-0011");
 script_bugtraq_id(7145);
 script_xref(name:"OSVDB", value:"14396");

 name["english"] = "MS03-009: Microsoft ISA Server DNS - Denial Of Service (331065)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to launch a denial of service attack against the remote
DNS application filter." );
 script_set_attribute(attribute:"description", value:
"A vulnerability in Microsoft ISA Server 2000 allows an attacker to
cause a denial of service in DNS services by sending a specially
crafted DNS request packet.  

Note that, to be vulnerable, the ISA Server must be manually
configured to publish an internal DNS server, which it does not do by
default." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for ISA Server 2000 :

http://www.microsoft.com/technet/security/bulletin/ms03-009.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P" );
script_end_attributes();

 
 summary["english"] = "Checks for ISA Server DNS HotFix SP1-256";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/registry_full_access");
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
 if ( hotfix_check_fversion(path:path, file:"Issfltr.dll", version:"3.0.1200.256") == HCF_OLDER )
 {
  set_kb_item(name:"SMB/Missing/MS03-009", value:TRUE);
  hotfix_security_note();
 }
 hotfix_check_fversion_end();
}
else 
{
 #superseded by SP2
 fix = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc/Hotfixes/SP1/365");
 if(fix) exit(0);

 fix = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc/Hotfixes/SP1/256");
 if(!fix) {
 set_kb_item(name:"SMB/Missing/MS03-009", value:TRUE);
 hotfix_security_note();
 }
}
