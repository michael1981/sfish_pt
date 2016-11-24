
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41422);
 script_version("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  libopensc2 (2009-03-17)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for libopensc2");
 script_set_attribute(attribute: "description", value: "Private data objects on smartcards initialized with OpenSC
could be accessed without authentication (CVE-2009-0368).

Only blank cards initialized with OpenSC are affected by
this problem. Affected cards need to be manually fixed,
updating the opensc package alone is not sufficient!

Please carefully read and follow the instructions on the
following web site if you are using PIN protected private
data objects on smart cards other than Oberthur, and you
have initialized those cards using OpenSC:
http://en.opensuse.org/Smart_Cards/Advisories
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for libopensc2");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=480262");
script_end_attributes();

 script_cve_id("CVE-2009-0368");
script_summary(english: "Check for the libopensc2 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"libopensc2-0.11.6-5.25.1", release:"SLES11", cpu:"i586") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"opensc-0.11.6-5.25.1", release:"SLES11", cpu:"i586") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libopensc2-0.11.6-5.25.1", release:"SLED11", cpu:"i586") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"opensc-0.11.6-5.25.1", release:"SLED11", cpu:"i586") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
