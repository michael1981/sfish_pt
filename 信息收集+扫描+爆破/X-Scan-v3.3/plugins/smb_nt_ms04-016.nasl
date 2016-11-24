#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(12267);
 script_version("$Revision: 1.17 $");

 script_cve_id("CVE-2004-0202");
 script_bugtraq_id(10487);
 script_xref(name:"OSVDB", value:"6742");

 name["english"] = "MS04-016: Vulnerability in DirectPlay Could Allow Denial of Service (839643)";
 script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"It is possible to crash the remote DirectPlay service." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of version of DirectPlay that is
vulnerable to a denial of service attack.  DirectPlay is a component
of DirectX and is frequently used by game developpers to create
networked multi-player games. 

An attacker may exploit this flaw by sending a malformed IDirectPlay
packet to a remote application using this service and cause it to
crash." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 
2003 :

http://www.microsoft.com/technet/security/bulletin/ms04-016.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
script_end_attributes();

 
 summary["english"] = "Checks for ms04-016 over the registry";
 script_summary(english:summary["english"]);
 
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

vers = get_kb_item("SMB/WindowsVersion");
if ( !vers ) exit(0);

dvers = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/DirectX/Version");
if ( !dvers ) exit(0);

if ( hotfix_check_sp(win2k:5, xp:2, win2003:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Dplayx.dll", version:"5.2.3790.163", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Dplayx.dll", version:"5.1.2600.1517", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"Dplayx.dll", version:"5.1.2600.148", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Dplayx.dll", version:"5.0.2195.6922", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Dplayx.dll", version:"5.1.2258.410", min_version:"5.1.0.0", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS04-016", value:TRUE);
 security_warning(get_kb_item("SMB/transport"));
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}

if ( vers == "5.0" )
{
  if (  ( dvers != "4.08.00.0400" ) &&
	( dvers != "4.08.00.0400" ) &&
	( dvers != "4.08.01.0881" ) &&
	( dvers != "4.08.01.0901" ) &&
	( dvers != "4.08.02.0134" ) &&
	( dvers != "4.09.00.0900" ) &&
	( dvers != "4.09.00.0901" ) &&
	( dvers != "4.09.00.0902" ) )
	exit (0);
} 


if ( vers == "5.1" )
{
  if (  ( dvers != "4.08.02.0134" ) &&
	( dvers != "4.09.00.0900" ) &&
	( dvers != "4.09.00.0901" ) &&
	( dvers != "4.09.00.0902" ) )
	exit (0);
} 


if ( vers == "5.2" )
{
  if (  ( dvers != "4.09.00.0900" ) &&
	( dvers != "4.09.00.0901" ) &&
	( dvers != "4.09.00.0902" ) )
	exit (0);
} 

if ( hotfix_missing(name:"KB839643") > 0 &&
     hotfix_missing(name:"KB839643-DirectX8") > 0 &&
     hotfix_missing(name:"KB839643-DirectX81") > 0 &&
     hotfix_missing(name:"KB839643-DirectX82") > 0 &&
     hotfix_missing(name:"KB839643-DirectX9")  > 0 )
	 {
 set_kb_item(name:"SMB/Missing/MS04-016", value:TRUE);
 hotfix_security_warning();
 }

