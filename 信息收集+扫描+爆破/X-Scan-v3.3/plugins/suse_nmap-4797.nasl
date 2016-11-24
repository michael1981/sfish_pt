#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#


if ( ! defined_func("bn_random") ) exit(0);


include("compat.inc");

if(description)
{
 script_id(29788);
 
 script_version ("$Revision: 1.8 $");

 name["english"] = "SuSE Security Update: Security update for nmap (nmap-4797)";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote SuSE system is missing the security patch nmap-4797." );
 script_set_attribute(attribute:"description", value:
"This update makes Nmap use the system PCRE library rather than its
own copy.  The system PCRE library has been updated to prevent a
security flaw in the way it handles malformed regular expressions.
Nmap does not contain any malformed or malicious regular expressions,
but using the system library is preferable.  Make sure you also
install the system PCRE update." );
 script_set_attribute(attribute:"solution", value:
"Install the security patch nmap-4797." );
 script_set_attribute(attribute:"risk_factor", value:"Low" );

script_end_attributes();

 
 summary["english"] = "Checks for the nmap-4797 package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");


if ( rpm_check( reference:"nmap-4.00-14.6", release:"SLES10") )
{
	security_note(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"nmap-gtk-4.00-14.6", release:"SLES10") )
{
	security_note(port:0, extra:rpm_report_get());
	exit(0);
}
