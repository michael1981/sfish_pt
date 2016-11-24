#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(40971);
 script_version("$Revision: 1.1 $");

 script_name(english: "Solaris 5.8 (sparc) : 142188-01");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 142188-01");
 script_set_attribute(attribute: "description", value:
'StarOffice 9 (Solaris): Update 3 (requires Update 2).
Date this patch was last updated by Sun : Sep/11/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-142188-01-1");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_end_attributes();

 script_summary(english: "Check for patch 142188-01");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"142188-01", obsoleted_by:"", package:"ooobasis31-ar-res", version:"3.1.0,REV=11.2009.04.23");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"142188-01", obsoleted_by:"", package:"ooobasis31-calc", version:"3.1.0,REV=11.2009.04.23");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"142188-01", obsoleted_by:"", package:"ooobasis31-core01", version:"3.1.0,REV=11.2009.04.23");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"142188-01", obsoleted_by:"", package:"ooobasis31-core04", version:"3.1.0,REV=11.2009.04.23");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"142188-01", obsoleted_by:"", package:"ooobasis31-core05", version:"3.1.0,REV=11.2009.04.23");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"142188-01", obsoleted_by:"", package:"ooobasis31-de-res", version:"3.1.0,REV=11.2009.04.23");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"142188-01", obsoleted_by:"", package:"ooobasis31-en-US-res", version:"3.1.0,REV=11.2009.04.23");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"142188-01", obsoleted_by:"", package:"ooobasis31-es-res", version:"3.1.0,REV=11.2009.04.23");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"142188-01", obsoleted_by:"", package:"ooobasis31-fr-res", version:"3.1.0,REV=11.2009.04.23");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"142188-01", obsoleted_by:"", package:"ooobasis31-hu-res", version:"3.1.0,REV=11.2009.04.23");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"142188-01", obsoleted_by:"", package:"ooobasis31-it-res", version:"3.1.0,REV=11.2009.04.23");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"142188-01", obsoleted_by:"", package:"ooobasis31-nl-res", version:"3.1.0,REV=11.2009.04.23");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"142188-01", obsoleted_by:"", package:"ooobasis31-pl-res", version:"3.1.0,REV=11.2009.04.23");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"142188-01", obsoleted_by:"", package:"ooobasis31-pt-BR-res", version:"3.1.0,REV=11.2009.04.23");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"142188-01", obsoleted_by:"", package:"ooobasis31-pt-res", version:"3.1.0,REV=11.2009.04.23");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"142188-01", obsoleted_by:"", package:"ooobasis31-ru-res", version:"3.1.0,REV=11.2009.04.23");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"142188-01", obsoleted_by:"", package:"ooobasis31-sv-res", version:"3.1.0,REV=11.2009.04.23");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"142188-01", obsoleted_by:"", package:"ooobasis31-writer", version:"3.1.0,REV=11.2009.04.23");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"142188-01", obsoleted_by:"", package:"openofficeorg-ure", version:"1.5.0,REV=11.2009.04.23");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
