
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(42418);
 script_version("$Revision: 1.1 $");
 script_name(english: "SuSE 11.1 Security Update:  mozilla-nspr (2009-11-04)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for mozilla-nspr");
 script_set_attribute(attribute: "description", value: "This update fixes a bug in the Mozilla NSPR helper
libraries, which could be used by remote attackers to
potentially execute code via javascript vectors.

MFSA 2009-59 / CVE-2009-1563: Security researcher Alin Rad
Pop of Secunia Research reported a heap-based buffer
overflow in Mozilla's string to floating point number
conversion routines. Using this vulnerability an attacker
could craft some malicious JavaScript code containing a
very long string to be converted to a floating point number
which would result in improper memory allocation and the
execution of an arbitrary memory location. This
vulnerability could thus be leveraged by the attacker to
run arbitrary code on a victim's computer.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for mozilla-nspr");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=546371");
script_end_attributes();

 script_cve_id("CVE-2009-1563");
script_summary(english: "Check for the mozilla-nspr package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"mozilla-nspr-4.8.2-1.1.1", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-4.8.2-1.1.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-32bit-4.8.2-1.1.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-devel-4.8.2-1.1.1", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-devel-4.8.2-1.1.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");
