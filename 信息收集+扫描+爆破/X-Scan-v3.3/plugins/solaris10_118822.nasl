#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(19367);
 script_version("$Revision: 1.29 $");

 script_name(english: "Solaris 10 (sparc) : 118822-30");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 118822-30");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10: kernel Patch.
Date this patch was last updated by Sun : Feb/23/06');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-118822-30-1");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_end_attributes();

 script_summary(english: "Check for patch 118822-30");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"FJSVhea", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"FJSVmdb", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"FJSVmdbr", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"FJSVpiclu", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNW1394", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWarcr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWcakr", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWcakr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWcakr", version:"11.10.0,REV=2005.08.25.02.12");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWcart200", version:"11.10.0,REV=2005.08.10.02.13");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWckr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWcnetr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWcpr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWcsd", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWcsl", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWcslr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWcsr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWcsu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWcti2", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWdfbh", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWdrcr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWdrr", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWdrr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWdtrc", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWdtrp", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWefc", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWefc", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWftdur", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWhea", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWib", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWidn", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWintgige", version:"11.10.0,REV=2005.09.15.00.13");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWipfr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWipfu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWkey", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWluxl", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWmdb", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWmdbr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWmddr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWmdr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWmdu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWnfsckr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWopenssl-commands", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWopenssl-libraries", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWpcmci", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWpiclu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWpl5v", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWqos", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWrcmdc", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWscpu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWsndmr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWsndmu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWtoo", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWusb", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWust1", version:"11.10.0,REV=2005.08.10.02.13");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWwrsd", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWwrsm", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"118822-30", obsoleted_by:"118833-36 ", package:"SUNWxge", version:"11.10.0,REV=2005.01.21.15.53");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
