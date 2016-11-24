#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11143);
 script_version("$Revision: 1.19 $");

 script_cve_id("CVE-2002-0368");
 script_bugtraq_id(4881);
 script_xref(name:"OSVDB", value:"863");
 script_xref(name:"IAVA", value:"2002-b-0002"); 

 script_name(english:"MS02-025: Exchange 2000 Exhaust CPU Resources (320436)");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to launch a denial of service attack against the remote
mail server." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Exchange Server 2000.  The remote version
of this software contains a flaw that allows an attacker to cause a
temporary denial of service. 

To do this, the attacker needs to send an email message with malformed
attributes.  CPU utilization will spike at 100% until the message has
been processed." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Exchange 2000 :

http://www.microsoft.com/technet/security/bulletin/ms02-025.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 script_summary(english:"Checks for MS Hotfix Q320436, DOS on Exchange 2000");
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


server = hotfix_check_nt_server();
if (!server) exit (0);

version = get_kb_item ("SMB/Exchange/Version");
if (!version || (version != 60)) exit (0);

sp = get_kb_item ("SMB/Exchange/SP");
if (sp && (sp >= 3)) exit (0);

if (is_accessible_share())
{
 path = get_kb_item ("SMB/Exchange/Path") + "\bin";
 if ( hotfix_is_vulnerable (os:"5.0", file:"Exprox.dll", version:"6.0.5770.91", dir:path) )
 {
 set_kb_item(name:"SMB/Missing/MS02-025", value:TRUE);
 security_warning(get_kb_item("SMB/transport"));
 }
 hotfix_check_fversion_end();
}
else if (hotfix_missing (name:"320436") > 0 )
 {
 set_kb_item(name:"SMB/Missing/MS02-025", value:TRUE);
 hotfix_security_warning();
 }
