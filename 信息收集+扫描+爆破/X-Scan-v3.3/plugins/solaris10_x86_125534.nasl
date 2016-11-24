#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(41944);
 script_version("$Revision: 1.3 $");

 script_name(english: "Solaris 10 (x86) : 125534-15");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 125534-15");
 script_set_attribute(attribute: "description", value:
'Gnome 2.6.0_x86: Trusted Extension Runtime Patch.
Date this patch was last updated by Sun : Sep/30/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-125534-15-1");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_end_attributes();

 script_summary(english: "Check for patch 125534-15");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"125534-15", obsoleted_by:"", package:"SUNWtgnome-tsol-libs-devel", version:"2.6.0,REV=101.0.3.2006.09.05.04.14");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"125534-15", obsoleted_by:"", package:"SUNWtgnome-tsol-libs", version:"2.6.0,REV=101.0.3.2006.09.05.04.14");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"125534-15", obsoleted_by:"", package:"SUNWtgnome-tsoljdsdevmgr", version:"2.6,REV=101.0.3.2006.10.16.04.14");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"125534-15", obsoleted_by:"", package:"SUNWtgnome-tsoljdslabel", version:"2.6.0,REV=101.0.3.2006.11.08.04.15");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"125534-15", obsoleted_by:"", package:"SUNWtgnome-tsoljdsselmgr", version:"2.6.0,REV=101.0.3.2006.10.16.04.15");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"125534-15", obsoleted_by:"", package:"SUNWtgnome-tstripe", version:"2.6,REV=101.0.3.2006.11.10.16.12");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"125534-15", obsoleted_by:"", package:"SUNWtgnome-xagent", version:"2.6.0,REV=101.0.3.2006.10.16.10.31");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
