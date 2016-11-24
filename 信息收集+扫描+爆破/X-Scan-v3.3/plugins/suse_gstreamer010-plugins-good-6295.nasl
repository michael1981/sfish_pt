
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(42004);
 script_version ("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  gstreamer security update (gstreamer010-plugins-good-6295)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch gstreamer010-plugins-good-6295");
 script_set_attribute(attribute: "description", value: "Specially crafted files could cause integer overflows in
the PNG decoding module of GStreamer (CVE-2009-1932).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch gstreamer010-plugins-good-6295");
script_end_attributes();

script_cve_id("CVE-2009-1932");
script_summary(english: "Check for the gstreamer010-plugins-good-6295 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"gstreamer010-plugins-good-0.10.6-41.6", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"gstreamer010-plugins-good-doc-0.10.6-41.6", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"gstreamer010-plugins-good-extra-0.10.6-41.6", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
