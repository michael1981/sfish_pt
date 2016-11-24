#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(13552);
 script_version("$Revision: 1.46 $");

 script_name(english: "Solaris 9 (sparc) : 114332-25");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 114332-25");
 script_set_attribute(attribute: "description", value:
'SunOS 5.9: c2audit & *libbsm.so.1 Patch.
Date this patch was last updated by Sun : Nov/28/06');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-114332-25-1");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_end_attributes();

 script_summary(english: "Check for patch 114332-25");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"114332-25", obsoleted_by:"122300-06 ", package:"SUNWarc", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"114332-25", obsoleted_by:"122300-06 ", package:"SUNWcarx", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"114332-25", obsoleted_by:"122300-06 ", package:"SUNWcarx", version:"11.9.0,REV=2002.04.09.12.25");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"114332-25", obsoleted_by:"122300-06 ", package:"SUNWcsl", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"114332-25", obsoleted_by:"122300-06 ", package:"SUNWcslx", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"114332-25", obsoleted_by:"122300-06 ", package:"SUNWcsr", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"114332-25", obsoleted_by:"122300-06 ", package:"SUNWcstl", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"114332-25", obsoleted_by:"122300-06 ", package:"SUNWcstlx", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"114332-25", obsoleted_by:"122300-06 ", package:"SUNWcsu", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"114332-25", obsoleted_by:"122300-06 ", package:"SUNWcsxu", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"114332-25", obsoleted_by:"122300-06 ", package:"SUNWhea", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"114332-25", obsoleted_by:"122300-06 ", package:"SUNWvolr", version:"11.9.0,REV=2002.04.06.15.27");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
