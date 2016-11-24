#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(22959);
 script_version("$Revision: 1.16 $");

 script_name(english: "Solaris 10 (sparc) : 119900-10");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 119900-10");
 script_set_attribute(attribute: "description", value:
'GNOME 2.6.0: Gnome libtiff - library for reading and writing TIFF.
Date this patch was last updated by Sun : Oct/05/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-119900-10-1");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_end_attributes();

 script_summary(english: "Check for patch 119900-10");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"119900-10", obsoleted_by:"", package:"SUNWPython", version:"2.3.3,REV=10.0.3.2004.12.15.14.07");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"119900-10", obsoleted_by:"", package:"SUNWTiff-devel", version:"20.2.6.0,REV=10.0.3.2004.12.15.14.09");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"119900-10", obsoleted_by:"", package:"SUNWTiff", version:"20.2.6.0,REV=10.0.3.2004.12.15.14.09");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"119900-10", obsoleted_by:"", package:"SUNWgnome-img-viewer-share", version:"2.6.0,REV=10.0.3.2004.12.15.23.40");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
