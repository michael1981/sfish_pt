#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11534);
 script_version ("$Revision: 1.20 $");

 script_cve_id("CVE-2003-0110");
 script_bugtraq_id(7314);
 script_xref(name:"OSVDB", value:"6967");

 name["english"] = "MS03-012: Microsoft ISA Server Winsock Proxy DoS (331066)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to launch a denial of service attack against the remote
proxy server." );
 script_set_attribute(attribute:"description", value:
"A vulnerability in Microsoft Proxy Server 2.0 and ISA Server 2000
allows an attacker to cause a denial of service of the remote Winsock
proxy service by sending a specially crafted packet that would cause
100% CPU utilization on the remote host and make it unresponsive." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for ISA Server 2000 :

http://www.microsoft.com/technet/security/bulletin/ms03-012.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C" );
script_end_attributes();

 
 summary["english"] = "Checks for ISA Server HotFix SP1-257";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
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
 if ( hotfix_check_fversion(path:path, file:"W3proxy.exe", version:"3.0.1200.257") == HCF_OLDER )
 {
   set_kb_item(name:"SMB/Missing/MS03-012", value:TRUE);
   hotfix_security_hole();
 }
 hotfix_check_fversion_end();
}
else 
{
 #superseded by MS04-039
 fix = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc/Hotfixes/SP1/408");
 if(fix) exit(0);

 #superseded by SP2
 fix = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc/Hotfixes/SP1/365");
 if(fix) exit(0);

 fix = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc/Hotfixes/SP1/257");
 if(!fix) {
  set_kb_item(name:"SMB/Missing/MS03-012", value:TRUE);
  hotfix_security_hole();
 }
}
