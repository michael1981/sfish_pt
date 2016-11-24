#
# This script was written by Michael Scheidell <scheidell@fdma.com>
# based on template from Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable
# - Updated to use compat.inc, added CVSS score (11/20/2009)



include("compat.inc");

if(description)
{
 script_id(10806);
 script_version ("$Revision: 1.22 $");
 script_cve_id("CVE-2001-0662");
 script_bugtraq_id(3313);
 script_xref(name:"OSVDB", value:"673");
 
 script_name(english:"MS01-048: RPC Endpoint Mapper Malformed Request DoS (305399)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a denial of service vulnerability." );
 script_set_attribute(attribute:"description", value:
"The hotfix for the 'RPC Endpoint Mapper Service on NT 4 has not been applied'
problem has not been applied.

Because the endpoint mapper runs within the RPC service itself, exploiting this
vulnerability would cause the RPC service itself to fail, with the attendant loss
of any RPC-based services the server offers, as well as potential loss of some COM
functions. Normal service could be restored by rebooting the server." );
 script_set_attribute(attribute:"solution", value:
"See http://www.microsoft.com/technet/security/bulletin/ms01-048.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );


script_end_attributes();

 script_summary(english:"Determines whether the hotfix Q305399 is installed");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2009 Michael Scheidell");
 script_family(english:"Windows : Microsoft Bulletins");
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

#

include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

if ( hotfix_check_sp(nt:7) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q305399") > 0 ) 
	 {
 set_kb_item(name:"SMB/Missing/MS01-048", value:TRUE);
 hotfix_security_warning();
 }

