#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(27075);
 script_version("$Revision: 1.21 $");

 script_name(english: "Solaris 10 (sparc) : 127111-11");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 127111-11");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10: kernel patch.
Date this patch was last updated by Sun : Mar/20/08');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-127111-11-1");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_end_attributes();

 script_summary(english: "Check for patch 127111-11");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"FJSVfmd", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"FJSVhea", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"FJSVmdb", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"FJSVmdbr", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWarcr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWbtool", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWcakr", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWcakr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWcakr", version:"11.10.0,REV=2005.08.25.02.12");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWcakrnt2000", version:"11.10.0,REV=2006.08.08.12.13");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWcar", version:"11.10.0,REV=2005.08.10.02.13");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWcart200", version:"11.10.0,REV=2005.08.10.02.13");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWckr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWcpc", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWcpc", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWcpc", version:"11.10.0,REV=2005.07.25.02.27");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWcpr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWcry", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWcryr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWcsd", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWcsl", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWcslr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWcsr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWcstl", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWcsu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWdcar", version:"11.10.0,REV=2007.06.20.13.33");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWdrcr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWdrr", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWdrr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWdtrc", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWdtrp", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWefc", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWefc", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWesu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWfmd", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWhea", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWiopc", version:"11.10.0,REV=2006.07.11.11.28");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWkvmt200", version:"11.10.0,REV=2005.08.10.02.13");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWldomr", version:"11.10.0,REV=2006.10.04.00.26");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWldomu", version:"11.10.0,REV=2006.08.08.12.13");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWmdb", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWmdbr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWn2cp", version:"11.10.0,REV=2007.07.08.21.44");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWnfsckr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWnfssu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWnisu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWniumx", version:"11.10.0,REV=2007.06.20.13.33");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWnxge", version:"11.10.0,REV=2007.07.08.17.44");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWopenssl-libraries", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWpiclu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWpsu", version:"13.1,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWtoo", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWusb", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWust1", version:"11.10.0,REV=2005.08.10.02.13");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWust2", version:"11.10.0,REV=2007.07.08.17.44");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWypr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWypu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127111-11", obsoleted_by:"127127-11 ", package:"SUNWzoneu", version:"11.10.0,REV=2005.01.21.15.53");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
