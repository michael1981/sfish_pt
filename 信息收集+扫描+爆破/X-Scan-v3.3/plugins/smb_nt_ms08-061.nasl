#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(34406);
 script_version("$Revision: 1.6 $");

 script_cve_id("CVE-2008-2250", "CVE-2008-2251", "CVE-2008-2252");
 script_bugtraq_id(31651, 31652, 31653);
 script_xref(name:"OSVDB", value:"49054");
 script_xref(name:"OSVDB", value:"49055");
 script_xref(name:"OSVDB", value:"49056");

 name["english"] = "MS08-061: Microsoft Windows Kernel Multiple Privilege Elevation (954211)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"A local user can elevate his privileges on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the Windows kernel which is vulnerable
to a security flaw which may allow a local user to elevate his privileges
or to crash it (therefore causing a denial of service)." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003, Vista, 2008:

http://www.microsoft.com/technet/security/bulletin/ms08-061.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 summary["english"] = "Make sure update 954211 has been installed on the remote host";

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


if ( hotfix_check_sp(xp:4, win2003:3, win2k:6, vista:2) <= 0 ) exit(0);

if (is_accessible_share())
{
      if ( hotfix_is_vulnerable (os:"6.0", sp:1, file:"Win32k.sys", version:"6.0.6001.22265", min_version:"6.0.6001.20000", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:1, file:"Win32k.sys", version:"6.0.6001.18141", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"Win32k.sys", version:"6.0.6000.20917", min_version:"6.0.6000.20000", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"Win32k.sys", version:"6.0.6000.16750", dir:"\system32") ||

      hotfix_is_vulnerable (os:"5.2", sp:2, file:"Win32k.sys", version:"5.2.3790.4375", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Win32k.sys", version:"5.2.3790.3212", dir:"\system32") ||

      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Win32k.sys", version:"5.1.2600.3446", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:3, file:"Win32k.sys", version:"5.1.2600.5676", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Win32k.sys", version:"5.0.2195.7194", dir:"\system32") )
   	 {
 set_kb_item(name:"SMB/Missing/MS08-061", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end();
 exit (0);
}
