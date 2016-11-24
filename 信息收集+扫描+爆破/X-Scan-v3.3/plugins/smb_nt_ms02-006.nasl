#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10865);
 script_version("$Revision: 1.28 $");

 # "CVE-2002-0012" and "CVE-2002-0013" too?
 script_cve_id("CVE-2002-0053");
 script_bugtraq_id(4089);
 script_xref(name:"OSVDB", value:"4850");

 script_name(english:"MS02-006: Malformed SNMP Management Request Remote Overflow (314147)");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host." );
 script_set_attribute(attribute:"description", value:
"A buffer overrun is present in the SNMP service on the remote host. 
By sending a malformed management request, an attacker could cause a
denial of service and possibly cause code to run on the system in the
LocalSystem context." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows NT, 2000 and XP :

http://www.microsoft.com/technet/security/bulletin/ms02-006.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Determines the presence of hotfix Q314147");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
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


if ( hotfix_check_sp(nt:7, xp:1, win2k:3) <= 0 ) exit(0);

if ( hotfix_missing(name:"314147") > 0  )
 {
 set_kb_item(name:"SMB/Missing/MS02-006", value:TRUE);
 hotfix_security_hole();
 }
