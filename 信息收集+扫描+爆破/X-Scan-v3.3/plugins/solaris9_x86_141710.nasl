#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(39005);
 script_version("$Revision: 1.1 $");

 script_name(english: "Solaris 5.9 (x86) : 141710-01");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 141710-01");
 script_set_attribute(attribute: "description", value:
'Sun GlassFish Enterprise Server v2.1 Security Patch01, _x86: SVR4.
Date this patch was last updated by Sun : Jun/02/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-141710-01-1");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_end_attributes();

 script_summary(english: "Check for patch 141710-01");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"141710-01", obsoleted_by:"", package:"SUNWasJdbcDrivers", version:"9.1,REV=2007.09.07.14.07");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"141710-01", obsoleted_by:"", package:"SUNWasac", version:"9.1,REV=2007.09.07.13.59");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"141710-01", obsoleted_by:"", package:"SUNWasacee", version:"9.1,REV=2007.09.07.14.08");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"141710-01", obsoleted_by:"", package:"SUNWascml", version:"9.1,REV=2007.09.07.14.08");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"141710-01", obsoleted_by:"", package:"SUNWascmn", version:"9.1,REV=2007.09.07.14.02");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"141710-01", obsoleted_by:"", package:"SUNWascmnse", version:"9.1,REV=2007.09.07.14.08");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"141710-01", obsoleted_by:"", package:"SUNWasdem", version:"9.1,REV=2007.09.07.14.02");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"141710-01", obsoleted_by:"", package:"SUNWashdm", version:"9.1,REV=2007.09.07.14.07");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"141710-01", obsoleted_by:"", package:"SUNWasjdoc", version:"9.1,REV=2007.09.07.14.03");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"141710-01", obsoleted_by:"", package:"SUNWaslb", version:"9.1,REV=2007.09.07.14.04");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"141710-01", obsoleted_by:"", package:"SUNWasman", version:"9.1,REV=2007.09.07.14.03");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"141710-01", obsoleted_by:"", package:"SUNWasr", version:"9.1,REV=2007.09.07.14.03");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"141710-01", obsoleted_by:"", package:"SUNWasu", version:"9.1,REV=2007.09.07.13.59");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"141710-01", obsoleted_by:"", package:"SUNWasuee", version:"9.1,REV=2007.09.07.14.07");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"141710-01", obsoleted_by:"", package:"SUNWasut", version:"9.1,REV=2007.09.07.14.03");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"141710-01", obsoleted_by:"", package:"SUNWaswbcr", version:"9.1,REV=2007.09.07.14.08");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
