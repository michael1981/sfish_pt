#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(22985);
 script_version("$Revision: 1.31 $");

 script_name(english: "Solaris 5.10 (x86) : 119060-46");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 119060-46");
 script_set_attribute(attribute: "description", value:
'X11 6.6.2_x86: Xsun patch.
Date this patch was last updated by Sun : Jun/15/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-119060-46-1");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_end_attributes();

 script_summary(english: "Check for patch 119060-46");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119060-46", obsoleted_by:"", package:"SUNWxorg-client-docs", version:"6.8.2.5.10.0110,REV=0.2005.06.21");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119060-46", obsoleted_by:"", package:"SUNWxwacx", version:"6.6.2.7400,REV=0.2004.12.15");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119060-46", obsoleted_by:"", package:"SUNWxwfnt", version:"6.6.2.7400,REV=0.2004.12.15");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119060-46", obsoleted_by:"", package:"SUNWxwfs", version:"6.6.2.7400,REV=0.2004.12.15");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119060-46", obsoleted_by:"", package:"SUNWxwice", version:"6.6.2.7400,REV=0.2004.12.15");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119060-46", obsoleted_by:"", package:"SUNWxwinc", version:"6.6.2.7400,REV=0.2004.12.15");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119060-46", obsoleted_by:"", package:"SUNWxwman", version:"6.6.2.7400,REV=0.2004.12.15");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119060-46", obsoleted_by:"", package:"SUNWxwopt", version:"6.6.2.7400,REV=0.2004.12.15");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119060-46", obsoleted_by:"", package:"SUNWxwplt", version:"6.6.2.7400,REV=0.2004.12.15");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119060-46", obsoleted_by:"", package:"SUNWxwpmn", version:"6.6.2.7400,REV=0.2004.12.15");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119060-46", obsoleted_by:"", package:"SUNWxwrtl", version:"6.6.2.7400,REV=0.2004.12.15");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119060-46", obsoleted_by:"", package:"SUNWxwsrv", version:"6.6.2.7400,REV=0.2004.12.15");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119060-46", obsoleted_by:"", package:"SUNWxwxst", version:"6.6.2.7400,REV=0.2004.12.15");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
