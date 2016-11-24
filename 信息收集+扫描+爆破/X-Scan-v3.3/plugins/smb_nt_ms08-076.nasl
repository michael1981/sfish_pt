#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(35075);
 script_version("$Revision: 1.9 $");

 script_cve_id("CVE-2008-3009", "CVE-2008-3010");
 script_bugtraq_id(32653, 32654);
 script_xref(name:"OSVDB", value:"50558");
 script_xref(name:"OSVDB", value:"50559");
 
 script_name(english: "MS08-076: Vulnerabilities in Windows Media Components Could Allow Remote Code Execution (959807)");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the Media Components." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Windows Media Player/Components.

There is a vulnerability in the remote version of this software which may
allow an attacker to execute arbitrary code on the remote host thru flaws
in ISATAP and SPN." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003, Vista and Windows 2008 :

http://www.microsoft.com/technet/security/bulletin/ms08-076.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 summary["english"] = "Checks the version of Media Format";

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

port = kb_smb_transport ();


if ( hotfix_check_sp(xp:4, win2k:6, win2003:3, vista:2) <= 0 ) exit(0);


if (is_accessible_share())
{
 e = 0;

 # WMP
 e += hotfix_is_vulnerable (os:"5.0", file:"Strmdll.dll", version:"4.1.0.3937", dir:"\system32");
 e += hotfix_is_vulnerable (os:"5.1", file:"Strmdll.dll", version:"4.1.0.3937", dir:"\system32");
 e += hotfix_is_vulnerable (os:"5.2", file:"Strmdll.dll", version:"4.1.0.3937", dir:"\system32");

 # WMF Runtime and WMS on Vista/2k8
 e += hotfix_is_vulnerable (os:"6.0", sp:1, file:"Wmvcore.dll", version:"11.0.6001.7105", min_version:"11.0.6001.7100", dir:"\system32");
 e += hotfix_is_vulnerable (os:"6.0", sp:1, file:"Wmvcore.dll", version:"11.0.6001.7001", min_version:"11.0.6001.0", dir:"\system32");
 e += hotfix_is_vulnerable (os:"6.0", sp:0, file:"Wmvcore.dll", version:"11.0.6000.6346", min_version:"11.0.6000.0", dir:"\system32");
 e += hotfix_is_vulnerable (os:"6.0", sp:0, file:"Wmvcore.dll", version:"11.0.6000.6505", min_version:"11.0.6000.6500", dir:"\system32");
 e += hotfix_is_vulnerable (os:"6.0", file:"Wmsserver.dll", version:"9.5.6001.18161", dir:"\system32");

 # WMS on 2k3
 e += hotfix_is_vulnerable (os:"5.2", sp:2, file:"Wmsserver.dll", version:"9.1.1.5000", dir:"\system32");
 e += hotfix_is_vulnerable (os:"5.2", sp:1, file:"Wmsserver.dll", version:"9.1.1.3845", dir:"\system32");

 # WMF Runtime on 2k3 and XP x64
 e += hotfix_is_vulnerable (os:"5.2", sp:1, arch:"x86", file:"Wmvcore.dll", version:"10.0.0.3711", min_version:"10.0.0.0", dir:"\system32");
 e += hotfix_is_vulnerable (os:"5.2", sp:2, arch:"x86", file:"Wmvcore.dll", version:"10.0.0.4001", min_version:"10.0.0.0", dir:"\system32");
 e += hotfix_is_vulnerable (os:"5.2", sp:1, arch:"x64", file:"Wmvcore.dll", version:"10.0.0.3711", min_version:"10.0.0.0", dir:"\syswow64");
 e += hotfix_is_vulnerable (os:"5.2",       arch:"x64", file:"Wmvcore.dll", version:"10.0.0.3816", min_version:"10.0.0.3800", dir:"\syswow64");
 e += hotfix_is_vulnerable (os:"5.2", sp:2, arch:"x64", file:"Wmvcore.dll", version:"10.0.0.4001", min_version:"10.0.0.3900", dir:"\syswow64");

 # 32-bit WMF Runtime on XP x64
 e += hotfix_is_vulnerable (os:"5.2",       arch:"x64", file:"Wmvcore.dll", version:"11.0.5721.5251", min_version:"11.0.0.0", dir:"\system32");

 # WMF Runtime on XP SP3
 e += hotfix_is_vulnerable (os:"5.1", sp:3, file:"Wmvcore.dll", version:"9.0.0.4504", min_version:"9.0.0.0", dir:"\system32");
 e += hotfix_is_vulnerable (os:"5.1", sp:3, file:"Wmvcore.dll", version:"10.0.0.3703", min_version:"10.0.0.0", dir:"\system32");
 e += hotfix_is_vulnerable (os:"5.1", sp:3, file:"Wmvcore.dll", version:"10.0.0.4066", min_version:"10.0.0.4000", dir:"\system32");
 e += hotfix_is_vulnerable (os:"5.1", sp:3, file:"Wmvcore.dll", version:"10.0.0.4362", min_version:"10.0.0.4300", dir:"\system32");
 e += hotfix_is_vulnerable (os:"5.1", sp:3, file:"Wmvcore.dll", version:"11.0.5721.5251", min_version:"11.0.0.0", dir:"\system32");

 # WMF Runtime on XP SP2
 e += hotfix_is_vulnerable (os:"5.1", sp:2, file:"Wmvcore.dll", version:"9.0.0.3268", min_version:"9.0.0.0", dir:"\system32");
 e += hotfix_is_vulnerable (os:"5.1", sp:2, file:"Wmvcore.dll", version:"9.0.0.3358", min_version:"9.0.0.3300", dir:"\system32");
 e += hotfix_is_vulnerable (os:"5.1", sp:2, file:"Wmvcore.dll", version:"10.0.0.3703", min_version:"10.0.0.0", dir:"\system32");
 e += hotfix_is_vulnerable (os:"5.1", sp:2, file:"Wmvcore.dll", version:"10.0.0.4066", min_version:"10.0.0.4000", dir:"\system32");
 e += hotfix_is_vulnerable (os:"5.1", sp:2, file:"Wmvcore.dll", version:"10.0.0.4362", min_version:"10.0.0.4300", dir:"\system32");
 e += hotfix_is_vulnerable (os:"5.1", sp:2, file:"Wmvcore.dll", version:"11.0.5721.5251", min_version:"11.0.0.0", dir:"\system32");

 # WMS on w2k
 e += hotfix_is_vulnerable (os:"5.0", file:"Wmvcore.dll", version:"9.0.0.3268", dir:"\system32");
 e +=  hotfix_is_vulnerable (os:"5.0", file:"Nscm.exe", version:"4.1.0.3936");

 if ( e ) {
 set_kb_item(name:"SMB/Missing/MS08-076", value:TRUE);
 hotfix_security_hole();
 }

   hotfix_check_fversion_end(); 
}
