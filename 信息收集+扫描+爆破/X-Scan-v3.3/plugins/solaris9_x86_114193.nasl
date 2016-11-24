#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(16091);
 script_version("$Revision: 1.26 $");

 script_name(english: "Solaris 9 (x86) : 114193-36");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 114193-36");
 script_set_attribute(attribute: "description", value:
'SunOS 5.9_x86: wbem Patch.
Date this patch was last updated by Sun : Aug/01/07');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-114193-36-1");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_end_attributes();

 script_summary(english: "Check for patch 114193-36");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"114193-36", obsoleted_by:"", package:"SUNWdclnt", version:"1.0,REV=2002.10.31.18.39");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"114193-36", obsoleted_by:"", package:"SUNWlvma", version:"1.0,REV=2002.10.31.18.39");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"114193-36", obsoleted_by:"", package:"SUNWmc", version:"11.9,REV=2002.10.31.18.39");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"114193-36", obsoleted_by:"", package:"SUNWmcc", version:"11.9,REV=2002.10.31.18.39");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"114193-36", obsoleted_by:"", package:"SUNWmccom", version:"11.9,REV=2002.10.31.18.39");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"114193-36", obsoleted_by:"", package:"SUNWmga", version:"1.0,REV=2002.10.31.18.39");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"114193-36", obsoleted_by:"", package:"SUNWpmgr", version:"3.0,REV=2002.10.31.18.39");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"114193-36", obsoleted_by:"", package:"SUNWwbapi", version:"2.5,REV=2002.10.31.18.39");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"114193-36", obsoleted_by:"", package:"SUNWwbcor", version:"2.5,REV=2002.10.31.18.39");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"114193-36", obsoleted_by:"", package:"SUNWwbcou", version:"2.5,REV=2002.10.31.18.39");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"114193-36", obsoleted_by:"", package:"SUNWwbdev", version:"2.5,REV=2002.10.31.18.39");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"114193-36", obsoleted_by:"", package:"SUNWwbmc", version:"11.9,REV=2002.10.31.18.39");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"114193-36", obsoleted_by:"", package:"SUNWwbpro", version:"2.0,REV=2002.10.31.18.39");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
