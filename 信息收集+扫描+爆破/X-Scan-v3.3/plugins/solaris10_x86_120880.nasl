#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(22996);
 script_version("$Revision: 1.13 $");

 script_name(english: "Solaris 5.10 (x86) : 120880-08");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 120880-08");
 script_set_attribute(attribute: "description", value:
'Sun Ray Core Services version 3.1 Patch Update SunOS 5.10_x86.
Date this patch was last updated by Sun : Nov/26/08');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-120880-08-1");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_end_attributes();

 script_summary(english: "Check for patch 120880-08");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120880-08", obsoleted_by:"", package:"SUNWuta", version:"3.1_32,REV=2005.08.24.08.55");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120880-08", obsoleted_by:"", package:"SUNWutesa", version:"3.1_32,REV=2005.08.24.08.55");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120880-08", obsoleted_by:"", package:"SUNWutfw", version:"3.1_32,REV=2005.08.24.08.55");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120880-08", obsoleted_by:"", package:"SUNWutgsm", version:"3.1_32,REV=2005.08.24.08.55");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120880-08", obsoleted_by:"", package:"SUNWutkio", version:"3.1_32,REV=2005.08.24.08.55");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120880-08", obsoleted_by:"", package:"SUNWutm", version:"3.1_32,REV=2005.08.24.08.55");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120880-08", obsoleted_by:"", package:"SUNWuto", version:"3.1_32,REV=2005.08.24.08.55");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120880-08", obsoleted_by:"", package:"SUNWutps", version:"3.1_32,REV=2005.08.24.08.55");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120880-08", obsoleted_by:"", package:"SUNWutr", version:"3.1_32,REV=2005.08.24.08.55");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120880-08", obsoleted_by:"", package:"SUNWutsto", version:"3.1_32,REV=2005.08.24.08.55");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120880-08", obsoleted_by:"", package:"SUNWutu", version:"3.1_32,REV=2005.08.24.08.55");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
