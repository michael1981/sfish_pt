#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(13140);
 script_version("$Revision: 1.16 $");

 script_name(english: "Solaris 7 (sparc) : 108376-46");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 108376-46");
 script_set_attribute(attribute: "description", value:
'OpenWindows 3.6.1: Xsun Patch.
Date this patch was last updated by Sun : Nov/28/05');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-108376-46-1");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_end_attributes();

 script_summary(english: "Check for patch 108376-46");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"108376-46", obsoleted_by:"", package:"SUNWxwfnt", version:"3.7.2101,REV=0.98.08.19");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"108376-46", obsoleted_by:"", package:"SUNWxwice", version:"3.7.2100,REV=0.98.08.05");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"108376-46", obsoleted_by:"", package:"SUNWxwicx", version:"3.7.2101,REV=0.98.08.26");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"108376-46", obsoleted_by:"", package:"SUNWxwinc", version:"3.7.2100,REV=0.98.08.05");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"108376-46", obsoleted_by:"", package:"SUNWxwman", version:"3.7.2100,REV=0.98.08.05");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"108376-46", obsoleted_by:"", package:"SUNWxwopt", version:"3.7.2100,REV=0.98.08.05");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"108376-46", obsoleted_by:"", package:"SUNWxwplt", version:"3.7.2103,REV=0.98.08.26");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"108376-46", obsoleted_by:"", package:"SUNWxwplx", version:"3.7.2102,REV=0.98.08.26");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"108376-46", obsoleted_by:"", package:"SUNWxwpmn", version:"3.7.2100,REV=0.98.08.05");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"108376-46", obsoleted_by:"", package:"SUNWxwslb", version:"3.7.2100,REV=0.98.08.05");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
