#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(13408);
 script_version("$Revision: 1.20 $");

 script_name(english: "Solaris 8 (x86) : 108774-28");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 108774-28");
 script_set_attribute(attribute: "description", value:
'SunOS 5.8_x86: IIIM and X Input & Output Method patch.
Date this patch was last updated by Sun : May/27/08');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-108774-28-1");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_end_attributes();

 script_summary(english: "Check for patch 108774-28");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"108774-28", obsoleted_by:"", package:"JSatsvw", version:"1.0,REV=1999.12.08.12.17");
e +=  solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"108774-28", obsoleted_by:"", package:"SUNWiiimr", version:"1.0,REV=1.0.38.1");
e +=  solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"108774-28", obsoleted_by:"", package:"SUNWiiimu", version:"1.0,REV=1.0.38.1");
e +=  solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"108774-28", obsoleted_by:"", package:"SUNWjexpl", version:"1.0,REV=1999.12.08.15.55");
e +=  solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"108774-28", obsoleted_by:"", package:"SUNWjpxpl", version:"1.2,REV=1999.12.08.15.55");
e +=  solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"108774-28", obsoleted_by:"", package:"SUNWjuxpl", version:"1.2,REV=1999.12.09.13.04");
e +=  solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"108774-28", obsoleted_by:"", package:"SUNWjwncx", version:"1.2,REV=1999.12.24.12.19");
e +=  solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"108774-28", obsoleted_by:"", package:"SUNWxi18n", version:"4.0,REV=1.0.38.2");
e +=  solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"108774-28", obsoleted_by:"", package:"SUNWxim", version:"4.0,REV=1.0.38.1");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
