#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(24216);
 script_version ("$Revision: 1.18 $");
 name["english"] = "Solaris 7 (sparc) : 113886-49";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing Sun Security Patch number 113886-49
(OpenGL 1.3: OpenGL Patch for Solaris (32-bit)).

Date this patch was last updated by Sun : Thu Nov 13 05:03:25 MST 2008

You should install this patch for your system to be up-to-date." );
 script_set_attribute(attribute:"solution", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-113886-49-1" );
 script_set_attribute(attribute:"risk_factor", value:"High" );


 script_end_attributes();

 
 summary["english"] = "Check for patch 113886-49"; 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"113886-49", obsoleted_by:"", package:"SUNWgldoc", version:"1.3,REV=2002.12.16");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"113886-49", obsoleted_by:"", package:"SUNWgldp", version:"1.3,REV=2002.12.16");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"113886-49", obsoleted_by:"", package:"SUNWglh", version:"1.3,REV=2002.12.16");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"113886-49", obsoleted_by:"", package:"SUNWglrt", version:"1.3,REV=2002.12.16");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"113886-49", obsoleted_by:"", package:"SUNWglrtu", version:"1.3,REV=2002.12.16");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"113886-49", obsoleted_by:"", package:"SUNWglsr", version:"1.3,REV=2002.12.16");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"113886-49", obsoleted_by:"", package:"SUNWglsrz", version:"1.3,REV=2002.12.16");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
