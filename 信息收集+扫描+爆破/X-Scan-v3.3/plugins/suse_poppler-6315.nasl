
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41578);
 script_version ("$Revision: 1.3 $");
 script_name(english: "SuSE Security Update:  Security update for poppler (poppler-6315)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch poppler-6315");
 script_set_attribute(attribute: "description", value: "This update of poppler: fix various security bugs that
occur while decoding JBIG2 (CVE-2009-0146, CVE-2009-0147,
CVE-2009-0165, CVE-2009-0166, CVE-2009-0799, CVE-2009-0800,
CVE-2009-1179, CVE-2009-1180, CVE-2009-1181, CVE-2009-1182,
CVE-2009-1183).

Further a denial of service bug in function
FormWidgetChoice::loadDefaults() (CVE-2009-0755) and
JBIG2Stream::readSymbolDictSeg() (CVE-2009-0756) was closed
that could be triggered via malformed PDF files.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch poppler-6315");
script_end_attributes();

script_cve_id("CVE-2009-0146", "CVE-2009-0147", "CVE-2009-0165", "CVE-2009-0166", "CVE-2009-0755", "CVE-2009-0756", "CVE-2009-0799", "CVE-2009-0800", "CVE-2009-1179", "CVE-2009-1180", "CVE-2009-1181", "CVE-2009-1182", "CVE-2009-1183");
script_summary(english: "Check for the poppler-6315 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"poppler-0.4.4-19.23", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"poppler-glib-0.4.4-19.23", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"poppler-qt-0.4.4-19.23", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
