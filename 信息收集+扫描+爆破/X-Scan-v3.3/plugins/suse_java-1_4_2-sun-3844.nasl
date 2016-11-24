
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29472);
 script_version ("$Revision: 1.9 $");
 script_name(english: "SuSE Security Update:  Security update for Java (java-1_4_2-sun-3844)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch java-1_4_2-sun-3844");
 script_set_attribute(attribute: "description", value: "The Sun JAVA JDK 1.4.2 was upgraded to release 15 to fix
various bugs, including the following security bugs:

CVE-2007-2788 / CVE-2007-3004: Integer overflow in the
embedded ICC profile image parser in Sun Java Development
Kit (JDK), allows remote attackers to execute arbitrary
code or cause a denial of service (JVM crash) via a crafted
JPEG or BMP file.

CVE-2007-2789 / CVE-2007-3005: The BMP image parser in Sun
Java Development Kit (JDK), on Unix/Linux systems, allows
remote attackers to trigger the opening of arbitrary local
files via a crafted BMP file, which causes a denial of
service (system hang) in certain cases such as /dev/tty,
and has other unspecified impact.

CVE-2007-0243: Buffer overflow in Sun JDK and Java Runtime
Environment (JRE) allows applets to gain privileges via a
GIF image with a block with a 0 width field, which triggers
memory corruption.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch java-1_4_2-sun-3844");
script_end_attributes();

 script_cve_id("CVE-2007-0243", "CVE-2007-2788", "CVE-2007-2789");
script_summary(english: "Check for the java-1_4_2-sun-3844 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"java-1_4_2-sun-1.4.2.15-2.1", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-alsa-1.4.2.15-2.1", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-devel-1.4.2.15-2.1", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-jdbc-1.4.2.15-2.1", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-plugin-1.4.2.15-2.1", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-1.4.2.15-2.1", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-alsa-1.4.2.15-2.1", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-demo-1.4.2.15-2.1", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-devel-1.4.2.15-2.1", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-jdbc-1.4.2.15-2.1", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-plugin-1.4.2.15-2.1", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-src-1.4.2.15-2.1", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
