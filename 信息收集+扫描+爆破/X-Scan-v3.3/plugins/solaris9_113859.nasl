#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(23494);
 script_version("$Revision: 1.8 $");

 script_name(english: "Solaris 5.9 (sparc) : 113859-04");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 113859-04");
 script_set_attribute(attribute: "description", value:
'SunOS 5.9 5.10: Sun ONE Directory Server 5.1 patch.
Date this patch was last updated by Sun : Mar/15/05');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-113859-04-1");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_end_attributes();

 script_summary(english: "Check for patch 113859-04");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"113859-04", obsoleted_by:"", package:"IPLTadcon", version:"5.1,REV=2002.03.01.11.57");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"113859-04", obsoleted_by:"", package:"IPLTadmin", version:"5.1,REV=2002.03.01.11.58");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"113859-04", obsoleted_by:"", package:"IPLTcons", version:"5.1,REV=2002.03.01.11.58");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"113859-04", obsoleted_by:"", package:"IPLTdscon", version:"5.1,REV=2002.03.01.11.58");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"113859-04", obsoleted_by:"", package:"IPLTdsu", version:"5.1,REV=2002.03.01.12.01");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"113859-04", obsoleted_by:"", package:"IPLTjss", version:"3.1,REV=2002.03.01.12.01");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"113859-04", obsoleted_by:"", package:"IPLTnls", version:"3.1,REV=2002.03.01.12.02");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"113859-04", obsoleted_by:"", package:"IPLTnspr", version:"4.1.2,REV=2002.03.01.12.02");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"113859-04", obsoleted_by:"", package:"IPLTnss", version:"3.3.1,REV=2002.03.01.12.01");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"113859-04", obsoleted_by:"", package:"IPLTpldap", version:"1.4.1,REV=2002.03.01.12.02");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
