#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(26019);

 script_cve_id("CVE-2007-2931");
 script_bugtraq_id(25461);
 script_xref(name:"OSVDB", value:"40126");

 script_version("$Revision: 1.9 $");

 name["english"] = "MS07-054: Vulnerability in MSN Messenger and Windows Live Messenger Could Allow Remote Code Execution (942099)";

 script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Messenger service." );
 script_set_attribute(attribute:"description", value:
"The remote host is running MSN Messenger or Windows Live Messenger.

The version of Messenger used on the remote host is vulnerable
to a remote buffer overflow in the way it handles webcam and video
chat sessions.
An attacker may exploit this vulnerability to execute arbitrary code
on the remote host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for MSN Messenger 6.2, 7.0, 7.5 and 8.0 :

http://www.microsoft.com/technet/security/bulletin/ms07-054.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );


script_end_attributes();


 summary["english"] = "Checks for MS07-054";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);

 script_dependencies("smb_nt_ms04-010.nasl");
 if ( NASL_LEVEL >= 3206 )
  script_require_ports("SMB/Registry/HKLM/SOFTWARE/Classes/Installer/Products/C838BEBA7A1AD5C47B1EB83441062011/Version",
		       "SMB/Registry/HKLM/SOFTWARE/Classes/Installer/Products/0F007175D9BDA3B40BD3531AB45B39F9/Version");
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");

version =  get_kb_item("SMB/Registry/HKLM/SOFTWARE/Classes/Installer/Products/C838BEBA7A1AD5C47B1EB83441062011/Version");
if ( ! version )
{
 version =  get_kb_item("SMB/Registry/HKLM/SOFTWARE/Classes/Installer/Products/0F007175D9BDA3B40BD3531AB45B39F9/Version");
 if ( ! version ) exit(0);
}

a = ((version) & 0xFF000000) >> 24;
b = ((version & 0xFF0000)) >> 16;
c = version & 0xFFFF;

os = get_kb_item("SMB/WindowsVersion");

if ("5.0" >< os)
{
 if ( ( a < 7 ) ||
     ( (a == 7) && (b == 0) && (c < 820) ) )
 {
 set_kb_item(name:"SMB/Missing/MS07-054", value:TRUE);
 hotfix_security_hole();
 }
}
else
{
 if ( ( a < 8 ) ||
     ( (a == 8) && (b == 0) ) )
 {
 set_kb_item(name:"SMB/Missing/MS07-054", value:TRUE);
 hotfix_security_hole();
 }
}
