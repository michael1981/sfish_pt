#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(23327);
 script_version("$Revision: 1.3 $");

 script_name(english: "Solaris 5.8 (sparc) : 110938-22");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 110938-22");
 script_set_attribute(attribute: "description", value:
'Sun Management Center 3.0: (GA) Patch for Solaris 8 and Solaris 9.
Date this patch was last updated by Sun : Apr/07/05');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-110938-22-1");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_end_attributes();

 script_summary(english: "Check for patch 110938-22");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110938-22", obsoleted_by:"", package:"SUNWed", version:"1.1,REV=41.2000.12.14,OE=S2.6");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110938-22", obsoleted_by:"", package:"SUNWedag", version:"1.1,REV=41.2000.12.14,OE=S8");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110938-22", obsoleted_by:"", package:"SUNWedagx", version:"1.1,REV=41.2000.12.14,OE=S8");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110938-22", obsoleted_by:"", package:"SUNWedcom", version:"1.1,REV=41.2000.12.14,OE=S2.6");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110938-22", obsoleted_by:"", package:"SUNWesae", version:"3.0_Build41,REV=2.8.2000.12.19");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110938-22", obsoleted_by:"", package:"SUNWesaem", version:"3.0_Build41,REV=2.8.2000.12.19");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110938-22", obsoleted_by:"", package:"SUNWesagt", version:"3.0_Build41,REV=2.8.2000.12.19");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110938-22", obsoleted_by:"", package:"SUNWesamn", version:"3.0_Build41,REV=2.8.2000.12.19");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110938-22", obsoleted_by:"", package:"SUNWesasc", version:"3.0_Build41,REV=2.6.2000.12.19");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110938-22", obsoleted_by:"", package:"SUNWescaa", version:"3.0_Build41,REV=2.6.2000.12.19");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110938-22", obsoleted_by:"", package:"SUNWescam", version:"3.0_Build41,REV=2.6.2000.12.19");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110938-22", obsoleted_by:"", package:"SUNWescix", version:"3.0_Build41,REV=2.6.2000.12.19");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110938-22", obsoleted_by:"", package:"SUNWescli", version:"3.0_Build41,REV=2.6.2000.12.19");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110938-22", obsoleted_by:"", package:"SUNWesclt", version:"3.0_Build41,REV=2.6.2000.12.19");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110938-22", obsoleted_by:"", package:"SUNWescom", version:"3.0_Build41,REV=2.8.2000.12.19");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110938-22", obsoleted_by:"", package:"SUNWescon", version:"3.0_Build41,REV=2.6.2000.12.19");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110938-22", obsoleted_by:"", package:"SUNWesdb", version:"3.0_Build41,REV=2.8.2000.12.19");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110938-22", obsoleted_by:"", package:"SUNWesjp", version:"3.0_Build41,REV=2.6.2000.12.19");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110938-22", obsoleted_by:"", package:"SUNWesjrm", version:"3.0_Build41,REV=2.6.2000.12.19");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110938-22", obsoleted_by:"", package:"SUNWesmcp", version:"3.0_Build41,REV=2.8.2000.12.19");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110938-22", obsoleted_by:"", package:"SUNWesmod", version:"3.0_Build41,REV=2.8.2000.12.19");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110938-22", obsoleted_by:"", package:"SUNWesmsg", version:"3.0_Build41,REV=2.6.2000.12.19");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110938-22", obsoleted_by:"", package:"SUNWesora", version:"3.0,REV=2000.10.27");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110938-22", obsoleted_by:"", package:"SUNWessa", version:"3.0_Build41,REV=2.8.2000.12.19");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110938-22", obsoleted_by:"", package:"SUNWessdk", version:"3.0,REV=2000.12.19");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110938-22", obsoleted_by:"", package:"SUNWessmn", version:"3.0_Build41,REV=2.6.2000.12.19");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110938-22", obsoleted_by:"", package:"SUNWessrv", version:"3.0_Build41,REV=2.6.2000.12.19");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110938-22", obsoleted_by:"", package:"SUNWessta", version:"3.0_Build41,REV=2.8.2000.12.19");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110938-22", obsoleted_by:"", package:"SUNWessts", version:"3.0_Build41,REV=2.6.2000.12.19");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110938-22", obsoleted_by:"", package:"SUNWessvc", version:"3.0_Build41,REV=2.6.2000.12.19");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110938-22", obsoleted_by:"", package:"SUNWesweb", version:"3.0_Build41,REV=2.6.2000.12.19");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110938-22", obsoleted_by:"", package:"SUNWeswga", version:"3.0_Build40,REV=2.8.2000.12.08");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110938-22", obsoleted_by:"", package:"SUNWeswgs", version:"3.0_Build40,REV=2.8.2000.12.08");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110938-22", obsoleted_by:"", package:"SUNWmeta", version:"3.0_Build41,REV=2.8.2000.12.19");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110938-22", obsoleted_by:"", package:"SUNWsycfd", version:"3.0_Build41,REV=2.8.2000.12.19");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
