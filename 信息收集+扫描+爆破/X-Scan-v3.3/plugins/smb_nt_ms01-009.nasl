#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10615);
 script_version ("$Revision: 1.27 $");
 script_cve_id("CVE-2001-0017");
 script_bugtraq_id(2368);
 script_xref(name:"OSVDB", value:"511");
 
 script_name(english:"MS01-009: Malformed PPTP Packet Stream Remote DoS (283001)");
 
 script_set_attribute(attribute:"synopsis", value:
"A flaw in the remote PPTP implementation may allow an attacker to
cause a denial of service." );
 script_set_attribute(attribute:"description", value:
"The hotfix for the 'Malformed PPTP Packet Stream' problem has not been
applied.  This hotfix corrects a memory leak in Windows NT PPTP
implementation which may cause it to use all the resources of the
remote host. 

An attacker may use this flaw by sending malformed PPTP packets to the
remote host until no more memory is available.  This would result in a
denial of service of the remote service or the whole system." );
 script_set_attribute(attribute:"solution", value:
"http://www.microsoft.com/technet/security/bulletin/ms01-009.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 script_summary(english:"Determines whether the hotfix Q283001 is installed");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

#

include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

if ( hotfix_check_sp(nt:7) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q299444") > 0 &&
     hotfix_missing(name:"Q283001") > 0 ) 
	 {
 set_kb_item(name:"SMB/Missing/MS01-009", value:TRUE);
 hotfix_security_warning();
 }
