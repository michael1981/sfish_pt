#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10943);
 script_version("$Revision: 1.32 $");

 script_cve_id("CVE-2002-0071", "CVE-2002-0147", "CVE-2002-0149", "CVE-2002-0150",
               "CVE-2002-0224", "CVE-2002-0869", "CVE-2002-1180", "CVE-2002-1181",
               "CVE-2002-1182");
 script_bugtraq_id(4006, 4474, 4476, 4478, 4490, 6069, 6070, 6071, 6072);
 if (NASL_LEVEL >= 3000)
 {
  script_xref(name:"OSVDB", value:"768");
  script_xref(name:"OSVDB", value:"771");
  script_xref(name:"OSVDB", value:"3301");
  script_xref(name:"OSVDB", value:"3316");
  script_xref(name:"OSVDB", value:"3320");
  script_xref(name:"OSVDB", value:"3325");
  script_xref(name:"OSVDB", value:"3326");
  script_xref(name:"OSVDB", value:"3328");
  script_xref(name:"OSVDB", value:"3338");
  script_xref(name:"OSVDB", value:"3339");
  script_xref(name:"OSVDB", value:"13434");
  script_xref(name:"OSVDB", value:"17122");
  script_xref(name:"OSVDB", value:"17123");
  script_xref(name:"OSVDB", value:"17124");
  script_xref(name:"IAVA", value:"2002-A-0002");
 }

 script_name(english:"MS02-018: Cumulative Patch for Internet Information Services (327696)");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web
server." );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains multiple flaws in the Internet
Information Service (IIS), such as heap overflow, DoS, and XSS that
may allow an attacker to execute arbitrary code on the remote host
with SYSTEM privileges." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for IIS 4.0, 5.0, 5.1 :

http://www.microsoft.com/technet/security/bulletin/ms02-062.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Determines whether October 30, 2002 IIS Cumulative patches (Q327696) are installed");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

#

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

if ( hotfix_check_iis_installed() <= 0 ) exit(0);
if ( hotfix_check_sp(nt:7, win2k:3, xp:1 ) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", sp:0, file:"W3svc.dll", version:"5.1.2600.1125", dir:"\system32\inetsrv") ||
      hotfix_is_vulnerable (os:"5.0", file:"W3svc.dll", version:"5.0.2195.5995", dir:"\system32\inetsrv") ||
      hotfix_is_vulnerable (os:"4.0", file:"W3svc.dll", version:"4.2.780.1", dir:"\system32\inetsrv") )
 {
 set_kb_item(name:"SMB/Missing/MS02-018", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"Q811114") > 0 &&
          hotfix_missing(name:"Q327696") > 0  ) 
 {
 set_kb_item(name:"SMB/Missing/MS02-018", value:TRUE);
 hotfix_security_hole();
 }
     

