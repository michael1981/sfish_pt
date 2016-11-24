#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(40941);
 script_version("$Revision: 1.1 $");

 script_name(english: "Solaris 5.9 (sparc) : 142189-01");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 142189-01");
 script_set_attribute(attribute: "description", value:
'StarSuite 9 (Solaris): Update 3 (requires Update 2).
Date this patch was last updated by Sun : Sep/09/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-142189-01-1");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_end_attributes();

 script_summary(english: "Check for patch 142189-01");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"142189-01", obsoleted_by:"", package:"ooobasis31-calc", version:"3.1.0,REV=11.2009.04.23");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"142189-01", obsoleted_by:"", package:"ooobasis31-core01", version:"3.1.0,REV=11.2009.04.23");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"142189-01", obsoleted_by:"", package:"ooobasis31-core04", version:"3.1.0,REV=11.2009.04.23");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"142189-01", obsoleted_by:"", package:"ooobasis31-core05", version:"3.1.0,REV=11.2009.04.23");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"142189-01", obsoleted_by:"", package:"ooobasis31-en-US-res", version:"3.1.0,REV=11.2009.04.23");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"142189-01", obsoleted_by:"", package:"ooobasis31-ja-res", version:"3.1.0,REV=11.2009.04.23");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"142189-01", obsoleted_by:"", package:"ooobasis31-ko-res", version:"3.1.0,REV=11.2009.04.23");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"142189-01", obsoleted_by:"", package:"ooobasis31-writer", version:"3.1.0,REV=11.2009.04.23");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"142189-01", obsoleted_by:"", package:"ooobasis31-zh-CN-res", version:"3.1.0,REV=11.2009.04.23");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"142189-01", obsoleted_by:"", package:"ooobasis31-zh-TW-res", version:"3.1.0,REV=11.2009.04.23");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"142189-01", obsoleted_by:"", package:"openofficeorg-ure", version:"1.5.0,REV=11.2009.04.23");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
