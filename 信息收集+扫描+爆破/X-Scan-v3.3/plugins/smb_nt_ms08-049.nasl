#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(33878);
 script_version("$Revision: 1.5 $");

 script_cve_id("CVE-2008-1457", "CVE-2008-1456");
 script_bugtraq_id(30584, 30586);
 script_xref(name:"OSVDB", value:"47411");

 name["english"] = "MS08-049: Vulnerabilities in Event System Could Allow Remote Code Execution (950974)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the
Microsoft Event System." );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a vulnerability in the Event
System which might allow an attacker to execute arbitrary code on the
remote host. 

To exploit this vulnerability, an attacker with valid logon
credentials would need to send a malformed subscription request to the
remote Event System." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
Vista and 2008 :

http://www.microsoft.com/technet/security/bulletin/ms08-049.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C" );


script_end_attributes();

 
 summary["english"] = "Determines the presence of update 950974";

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

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

if ( hotfix_check_sp(xp:4, win2003:3, win2k:6, vista:2) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:2, file:"es.dll", version:"2001.12.4720.4282", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"es.dll", version:"2001.12.4720.3129", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:3, file:"es.dll", version:"2001.12.4414.706", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"es.dll", version:"2001.12.4414.320", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"es.dll", version:"2001.12.6930.16677", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"es.dll", version:"2001.12.6930.20818", min_version:"2001.12.6930.20000", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:1, file:"es.dll", version:"2001.12.6931.18057", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:1, file:"es.dll", version:"2001.12.6931.22162", min_version:"2001.12.6931.22000", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"es.dll", version:"2000.2.3550.0", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS08-049", value:TRUE);
 security_hole(get_kb_item("SMB/transport"));
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
