#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(18592);
 script_version ("$Revision: 1.6 $");

 script_cve_id("CVE-2005-3168");
 script_bugtraq_id(14093);
 script_xref(name:"OSVDB", value:"19995");
 
 name["english"] =  "Microsoft Update Rollup 1 for Windows 2000 SP4 missing";
 
 script_name(english:name["english"]);
 	     
 
 script_set_attribute(attribute:"synopsis", value:
"A security update is missing on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the Update Rollup 1 (URP1) for Windows 2000 SP4.

This update rollup contains several security fixes in addition to previously
released security patches." );
 script_set_attribute(attribute:"solution", value:
"http://support.microsoft.com/kb/891861/" );
 script_set_attribute(attribute:"cvss_vector", value:"CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );


script_end_attributes();

 		    
 
 summary["english"] = "Determines whether the URP1 is installed";
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

include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_func.inc");

if ( hotfix_check_sp(win2k:5) <= 0 ) exit(0);

if (is_accessible_share ())
{
 if ( hotfix_is_vulnerable (os:"5.0", file:"eventlog.dll", version:"5.0.2195.7036", dir:"\system32") )
   security_warning(get_kb_item("SMB/transport"));
 hotfix_check_fversion_end(); 
}
else if ( hotfix_missing(name:"Update Rollup 1") > 0 ) 
   security_warning(get_kb_item("SMB/transport"));
