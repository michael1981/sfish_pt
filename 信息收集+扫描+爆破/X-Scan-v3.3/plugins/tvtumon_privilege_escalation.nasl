#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(34432);
 script_version("$Revision: 1.5 $");

 script_cve_id("CVE-2008-4589");
 script_bugtraq_id(31737);
 script_xref(name:"OSVDB", value:"49122");

 script_name(english:"Lenovo Rescue and Recovery tvtumon.sys Filename Handling Local Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"A local user can elevate his privileges on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Lenovo Rescue and Recovery
monitor driver which is vulnerable to a heap overflow.  A local
attacker may exploit this flaw to elevate his privileges (SYSTEM) on
the remote host." );
 script_set_attribute(attribute:"solution", value:
"http://www-307.ibm.com/pc/support/site.wss/MIGR-70699.html" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Determines the version of Lenovo Rescue and Recovery driver");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

#

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

if (!is_accessible_share()) exit(0);

if ( hotfix_check_fversion(file:"\system32\drivers\tvtumon.sys", version:"4.20.403.0") == HCF_OLDER )
  hotfix_security_hole();

hotfix_check_fversion_end();
