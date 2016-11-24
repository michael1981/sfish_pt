#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(13510);
 script_version("$Revision: 1.16 $");

 script_name(english: "Solaris 9 (sparc) : 112233-12");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 112233-12");
 script_set_attribute(attribute: "description", value:
'SunOS 5.9: Kernel Patch.
Date this patch was last updated by Sun : Apr/21/04');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-112233-12-1");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_end_attributes();

 script_summary(english: "Check for patch 112233-12");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"FJSVhea", version:"11.9.0,REV=2002.04.09.12.25");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWarc", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWarcx", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWcar", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWcar", version:"11.9.0,REV=2002.04.09.12.25");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWcarx", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWcarx", version:"11.9.0,REV=2002.04.09.12.25");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWcpc", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWcpc", version:"11.9.0,REV=2002.04.09.12.25");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWcpcx", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWcpcx", version:"11.9.0,REV=2002.04.09.12.25");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWcpr", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWcpr", version:"11.9.0,REV=2002.04.09.12.25");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWcprx", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWcprx", version:"11.9.0,REV=2002.04.09.12.25");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWcsl", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWcslx", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWcsr", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWcstl", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWcstlx", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWcsu", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWcsxu", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWdrcrx", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWdrr", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWdrr", version:"11.9.0,REV=2002.04.09.12.25");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWdrrx", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWdrrx", version:"11.9.0,REV=2002.04.09.12.25");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWefclx", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWefcux", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWefcx", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWefcx", version:"11.9.0,REV=2003.01.10.11.57");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWfss", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWfssx", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWged", version:"3.1,REV=2002.01.30.9.0");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWgedu", version:"3.1,REV=2002.01.30.9.0");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWgedx", version:"3.1,REV=2002.01.30.9.0");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWhea", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWidn", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWidnx", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWkvm", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWkvm", version:"11.9.0,REV=2002.04.09.12.25");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWmdb", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWmdbx", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWncar", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWncarx", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWncau", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWncaux", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWnfscr", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWnfscx", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWnisu", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWpd", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWpdx", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWpiclu", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWpmu", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWpmux", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWsxr", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWusx", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWwrsax", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWwrsdx", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWwrsmx", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWwrsux", version:"11.9.0,REV=2002.04.06.15.27");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
