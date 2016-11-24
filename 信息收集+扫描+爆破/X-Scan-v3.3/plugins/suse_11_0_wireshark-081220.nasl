
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40152);
 script_version("$Revision: 1.4 $");
 script_name(english: "SuSE 11.0 Security Update:  wireshark (2008-12-20)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for wireshark");
 script_set_attribute(attribute: "description", value: "This update fixes problems that could crash wireshark when
processing compressed data and when processing rf5 files
(CVE-2008-3933, CVE-2008-3934) as well as CVE-2008-4680
(USB dissector crash), CVE-2008-4681 (Bluetooth RFCOMM
dissector crash), CVE-2008-4682 (Tamos CommView dissector
crash), CVE-2008-4683 (Bluetooth ACL dissector crash),
CVE-2008-4684 (PRP and MATE dissector crash) and
CVE-2008-4685 (Q.931 dissector crash). CVE-2008-5285 (SMTP
dissector infinite loop) and an infinite loop problem in
the WLCCP dissector
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for wireshark");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=422948");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=457525");
script_end_attributes();

 script_cve_id("CVE-2008-3933", "CVE-2008-3934", "CVE-2008-4680", "CVE-2008-4681", "CVE-2008-4682", "CVE-2008-4683", "CVE-2008-4684", "CVE-2008-4685", "CVE-2008-5285");
script_summary(english: "Check for the wireshark package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"wireshark-1.0.0-17.7", release:"SUSE11.0", cpu:"i586") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"wireshark-1.0.0-17.7", release:"SUSE11.0", cpu:"x86_64") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"wireshark-devel-1.0.0-17.7", release:"SUSE11.0", cpu:"i586") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"wireshark-devel-1.0.0-17.7", release:"SUSE11.0", cpu:"x86_64") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");
