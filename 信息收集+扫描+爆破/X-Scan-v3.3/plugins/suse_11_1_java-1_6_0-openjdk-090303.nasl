
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40238);
 script_version("$Revision: 1.3 $");
 script_name(english: "SuSE 11.1 Security Update:  java-1_6_0-openjdk (2009-03-03)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for java-1_6_0-openjdk");
 script_set_attribute(attribute: "description", value: "OpenJDK Java 1.6.0 was upgraded to build b14, fixing quite
a lot of security issues.

It fixes at least: 4486841 UTF8 decoder should adhere to
corrigendum to Unicode 3.0.1 CVE-2008-5351 6484091
FileSystemView leaks directory info CVE-2008-5350 aka SUN
SOLVE 246266 6497740 Limit the size of RSA public keys
CVE-2008-5349 6588160 jaas krb5 client leaks OS-level UDP
sockets (all platforms) CVE-2008-5348 6592792 Add
com.sun.xml.internal to the 'package.access' property in
$JAVA_HOME/lib/security/java.security CVE-2008-5347 aka SUN
SOLVE 246366 6721753 File.createTempFile produces guessable
file names CVE-2008-5360 6726779 ConvolveOp on USHORT
raster can cause the JVM crash. CVE-2008-5359 aka SUN SOLVE
244987 6733336 Crash on malformed font CVE-2008-5356 aka
SUN SOLVE 244987 6733959 Insufficient checks for
'Main-Class' manifest entry in JAR files CVE-2008-5354 aka
SUN SOLVE 244990 6734167 Calendar.readObject allows
elevation of privileges CVE-2008-5353 6751322 Vulnerability
report: Sun Java JRE TrueType Font Parsing Heap Overflow
CVE-2008-5357 aka SUN SOLVE 244987 6755943 Java JAR Pack200
Decompression should enforce stricter header checks
CVE-2008-5352 aka SUN SOLVE 244992 6766136 corrupted gif
image may cause crash in java splashscreen library.
CVE-2008-5358 aka SUN SOLVE 244987
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for java-1_6_0-openjdk");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=471829");
script_end_attributes();

 script_cve_id("CVE-2008-5347", "CVE-2008-5348", "CVE-2008-5349", "CVE-2008-5350", "CVE-2008-5351", "CVE-2008-5352", "CVE-2008-5353", "CVE-2008-5354", "CVE-2008-5356", "CVE-2008-5357", "CVE-2008-5358", "CVE-2008-5359", "CVE-2008-5360");
script_summary(english: "Check for the java-1_6_0-openjdk package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"java-1_6_0-openjdk-1.4_b14-24.2.1", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-openjdk-1.4_b14-24.2.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-openjdk-demo-1.4_b14-24.2.1", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-openjdk-demo-1.4_b14-24.2.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-openjdk-devel-1.4_b14-24.2.1", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-openjdk-devel-1.4_b14-24.2.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-openjdk-javadoc-1.4_b14-24.2.1", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-openjdk-javadoc-1.4_b14-24.2.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-openjdk-plugin-1.4_b14-24.2.1", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-openjdk-plugin-1.4_b14-24.2.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-openjdk-src-1.4_b14-24.2.1", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-openjdk-src-1.4_b14-24.2.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");
