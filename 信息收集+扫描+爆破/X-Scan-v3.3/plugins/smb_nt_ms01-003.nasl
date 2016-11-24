#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10603);
 script_version ("$Revision: 1.27 $");
 script_cve_id("CVE-2001-0006");
 script_bugtraq_id(2303);
 script_xref(name:"OSVDB", value:"499");
 
 script_name(english:"MS01-003: Winsock2ProtocolCatalogMutex Mutex Local DoS (279336)");
 
 script_set_attribute(attribute:"synopsis", value:
"A bug in the remote operating system allows a local user to disable the network
functions of the remote host." );
 script_set_attribute(attribute:"description", value:
"By default, Windows NT sets weak permissions on the Winsock mutex. A local user 
without any privilege may abuse these permissions to lock the mutex indefinitely 
and therefore disrupt the network operations of the remote host." );
 script_set_attribute(attribute:"solution", value:
"http://www.microsoft.com/technet/security/bulletin/ms01-003.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 script_summary(english:"Determines whether the hotfix Q279336 is installed");
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
if ( hotfix_missing(name:"Q299444") > 0 && hotfix_missing(name:"Q279336") > 0 ) 
	 {
 set_kb_item(name:"SMB/Missing/MS01-003", value:TRUE);
 hotfix_security_note();
 }
