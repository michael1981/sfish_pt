#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11215);
 script_version("$Revision: 1.18 $");

 script_cve_id("CVE-2002-1256");
 script_bugtraq_id(6367);
 script_xref(name:"OSVDB", value:"11799");

 name["english"] = "MS02-070: Flaw in SMB Signing Could Enable Group Policy to be Modified (329170)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to send unsigned SMB packets." );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a flaw in the SMB signing
implementation.  SMB signing is used to sign each packets sent between
a client and a server to protect them against man-in-the-middle
attacks. 

If the Domain policy is configured to force usage of SMB signing, it
is possible for an attacker to downgrade the communication to disable
SMB signing and try to launch man-in-the-middle attacks." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP and 2000 :

http://www.microsoft.com/technet/security/bulletin/ms02-070.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:A/AC:M/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
 summary["english"] = "Checks for MS Hotfix 329170";
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

if ( hotfix_check_sp(win2k:4, xp:2) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", sp:1, file:"Srv.sys", version:"5.1.2600.1154", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"Srv.sys", version:"5.1.2600.105", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.0", file:"Srv.sys", version:"5.0.2195.6110", dir:"\system32\drivers") )
 {
 set_kb_item(name:"SMB/Missing/MS02-070", value:TRUE);
 security_warning(get_kb_item("SMB/transport"));
 }
 
 hotfix_check_fversion_end();
 exit (0);
}
else
{
 if ( hotfix_check_sp(xp:2) == 0 && hotfix_missing(name:"896422") == 0 ) exit(0);
 if ( hotfix_missing(name:"Q329170") > 0 )
 {
 set_kb_item(name:"SMB/Missing/MS02-070", value:TRUE);
 hotfix_security_warning();
 }
}
