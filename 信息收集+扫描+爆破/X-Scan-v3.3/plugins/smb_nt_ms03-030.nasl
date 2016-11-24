#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11803);
 script_version ("$Revision: 1.28 $");

 script_cve_id("CVE-2003-0346");
 script_bugtraq_id(8262);
 script_xref(name:"IAVA", value:"2003-A-0024");
 script_xref(name:"OSVDB", value:"13389");

 name["english"] = "MS03-030: DirectX MIDI Overflow (819696)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through DirectX." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Windows with a version of
DirectX that is vulnerable to a buffer overflow in the module that
handles MIDI files. 

To exploit this flaw, an attacker needs to craft a rogue MIDI file and
send it to a user of this computer.  When the user attempts to read
the file, it will trigger the buffer overflow condition and the
attacker may gain a shell on this host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for DirectX :

http://www.microsoft.com/technet/security/bulletin/ms03-030.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Checks hotfix 819696";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
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

if ( hotfix_check_sp(nt:7, win2k:5, xp:2, win2003:1) <= 0 ) exit(0);

dvers = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/DirectX/Version");
if ( !dvers ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Quartz.dll", version:"6.4.3790.9", min_version:"6.4.0.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:0, file:"Quartz.dll", version:"6.5.1.902", min_version:"6.5.0.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Quartz.dll", version:"6.4.2600.1221", min_version:"6.4.0.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"Quartz.dll", version:"6.4.2600.113", min_version:"6.4.0.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", file:"Quartz.dll", version:"6.5.1.902", min_version:"6.5.0.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", sp:3, file:"Quartz.dll", version:"6.1.9.729", min_version:"6.1.0.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Quartz.dll", version:"6.5.1.902", min_version:"6.5.0.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Quartz.dll", version:"6.3.1.886", min_version:"6.3.0.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"Quartz.dll", version:"6.1.5.132", min_version:"6.1.0.0", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS03-030", value:TRUE);
 security_hole(get_kb_item("SMB/transport"));
 }
 
 hotfix_check_fversion_end();
 exit (0);
}
