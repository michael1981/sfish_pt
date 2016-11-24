#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(23739);
 script_version ("$Revision: 1.12 $");
 name["english"] = "Solaris 10 (i386) : 123612-05";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing Sun Security Patch number 123612-05
(X11 6.6.2_x86: Trusted Extensions patch).

Date this patch was last updated by Sun : Fri May 09 01:23:22 MDT 2008

You should install this patch for your system to be up-to-date." );
 script_set_attribute(attribute:"solution", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-123612-05-1" );
 script_set_attribute(attribute:"risk_factor", value:"High" );


 script_end_attributes();

 
 summary["english"] = "Check for patch 123612-05"; 
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

e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"123612-05", obsoleted_by:"", package:"SUNWxwinc", version:"6.6.2.7400,REV=0.2004.12.15");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"123612-05", obsoleted_by:"", package:"SUNWxwplt", version:"6.6.2.7400,REV=0.2004.12.15");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"123612-05", obsoleted_by:"", package:"SUNWxwrtl", version:"6.6.2.7400,REV=0.2004.12.15");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
