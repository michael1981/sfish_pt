#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(35199);
 script_version("$Revision: 1.5 $");

 script_name(english: "Solaris 10 (sparc) : 138888-08");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 138888-08");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10: Kernel Patch.
Date this patch was last updated by Sun : Apr/01/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-138888-08-1");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_end_attributes();

 script_summary(english: "Check for patch 138888-08");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"138888-08", obsoleted_by:"139555-08 ", package:"FJSVhea", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"138888-08", obsoleted_by:"139555-08 ", package:"FJSVmdbr", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"138888-08", obsoleted_by:"139555-08 ", package:"SUNWcakr", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"138888-08", obsoleted_by:"139555-08 ", package:"SUNWcakr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"138888-08", obsoleted_by:"139555-08 ", package:"SUNWcakr", version:"11.10.0,REV=2005.08.25.02.12");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"138888-08", obsoleted_by:"139555-08 ", package:"SUNWckr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"138888-08", obsoleted_by:"139555-08 ", package:"SUNWcsd", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"138888-08", obsoleted_by:"139555-08 ", package:"SUNWcsl", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"138888-08", obsoleted_by:"139555-08 ", package:"SUNWcslr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"138888-08", obsoleted_by:"139555-08 ", package:"SUNWcsr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"138888-08", obsoleted_by:"139555-08 ", package:"SUNWcsu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"138888-08", obsoleted_by:"139555-08 ", package:"SUNWdtrc", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"138888-08", obsoleted_by:"139555-08 ", package:"SUNWesu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"138888-08", obsoleted_by:"139555-08 ", package:"SUNWhea", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"138888-08", obsoleted_by:"139555-08 ", package:"SUNWidn", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"138888-08", obsoleted_by:"139555-08 ", package:"SUNWipfh", version:"11.10.0,REV=2006.05.09.21.15");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"138888-08", obsoleted_by:"139555-08 ", package:"SUNWipfu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"138888-08", obsoleted_by:"139555-08 ", package:"SUNWldomr", version:"11.10.0,REV=2006.10.04.00.26");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"138888-08", obsoleted_by:"139555-08 ", package:"SUNWmdb", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"138888-08", obsoleted_by:"139555-08 ", package:"SUNWmdbr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"138888-08", obsoleted_by:"139555-08 ", package:"SUNWncau", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"138888-08", obsoleted_by:"139555-08 ", package:"SUNWpd", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"138888-08", obsoleted_by:"139555-08 ", package:"SUNWpdu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"138888-08", obsoleted_by:"139555-08 ", package:"SUNWroute", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"138888-08", obsoleted_by:"139555-08 ", package:"SUNWsckmu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"138888-08", obsoleted_by:"139555-08 ", package:"SUNWssad", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"138888-08", obsoleted_by:"139555-08 ", package:"SUNWus", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"138888-08", obsoleted_by:"139555-08 ", package:"SUNWust1", version:"11.10.0,REV=2005.08.10.02.13");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"138888-08", obsoleted_by:"139555-08 ", package:"SUNWust2", version:"11.10.0,REV=2007.07.08.17.44");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
