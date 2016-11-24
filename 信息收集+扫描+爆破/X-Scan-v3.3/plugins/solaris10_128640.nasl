#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(35409);
 script_version("$Revision: 1.8 $");

 script_name(english: "Solaris 5.10 (sparc) : 128640-13");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 128640-13");
 script_set_attribute(attribute: "description", value:
'Sun GlassFish Enterprise Server v2.1 Patch05 [ 9.1_02 Patch011 ] S.
Date this patch was last updated by Sun : Sep/25/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-128640-13-1");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_end_attributes();

 script_summary(english: "Check for patch 128640-13");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"128640-13", obsoleted_by:"", package:"SUNWasJdbcDrivers", version:"9.1,REV=2007.09.07.15.10");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"128640-13", obsoleted_by:"", package:"SUNWasac", version:"9.1,REV=2007.09.07.14.58");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"128640-13", obsoleted_by:"", package:"SUNWascmn", version:"9.1,REV=2007.09.07.15.03");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"128640-13", obsoleted_by:"", package:"SUNWashdm", version:"9.1,REV=2007.09.07.15.10");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"128640-13", obsoleted_by:"", package:"SUNWasjdoc", version:"9.1,REV=2007.09.07.15.04");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"128640-13", obsoleted_by:"", package:"SUNWaslb", version:"9.1,REV=2007.09.07.15.05");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"128640-13", obsoleted_by:"", package:"SUNWasman", version:"9.1,REV=2007.09.07.15.04");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"128640-13", obsoleted_by:"", package:"SUNWasu", version:"9.1,REV=2007.09.07.14.57");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"128640-13", obsoleted_by:"", package:"SUNWasut", version:"9.1,REV=2007.09.07.15.04");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
