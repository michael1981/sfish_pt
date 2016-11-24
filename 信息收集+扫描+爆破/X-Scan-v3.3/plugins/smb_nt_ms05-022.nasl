#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(18025);
 script_cve_id("CVE-2005-0562");
 script_bugtraq_id(13114);
 script_xref(name:"OSVDB", value:"15468");

 script_version("$Revision: 1.14 $");

 name["english"] = "MS05-022: Vulnerability in MSN Messenger Could Lead to Remote Code Execution (896597)";

 script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Messenger service." );
 script_set_attribute(attribute:"description", value:
"The remote host is running MSN Messenger.

The version of MSN Messenger used on the remote host is vulnerable
to a remote buffer overflow in the way it handles GIF files (with
height and width fields).
An attacker may exploit this vulnerability to execute arbitrary code
on the remote host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for MSN Messenger 6.2 :

http://www.microsoft.com/technet/security/bulletin/ms05-022.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );


script_end_attributes();


 summary["english"] = "Checks for MS05-022";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);

 script_dependencies("smb_nt_ms04-010.nasl");
 script_require_keys("SMB/Registry/HKLM/SOFTWARE/Classes/Installer/Products/C838BEBA7A1AD5C47B1EB83441062011/Version");
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");

version =  get_kb_item("SMB/Registry/HKLM/SOFTWARE/Classes/Installer/Products/C838BEBA7A1AD5C47B1EB83441062011/Version");
if ( ! version ) exit(0);

a = ((version) & 0xFF000000) >> 24;
b = ((version & 0xFF0000)) >> 16;
c = version & 0xFFFF;

if ( ( a == 6 ) &&
     ( (b < 2) || ( (b == 2) && (c < 208) ) ) )
 {
 set_kb_item(name:"SMB/Missing/MS05-022", value:TRUE);
 hotfix_security_hole();
 }

