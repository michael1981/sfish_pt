
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if (NASL_LEVEL < 3000 ) exit(0);

if(description)
{
 script_id(39998);
 script_version("$Revision: 1.3 $");
 script_name(english: "SuSE 11.0 Security Update:  java-1_5_0-sun (2009-03-27)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for java-1_5_0-sun");
 script_set_attribute(attribute: "description", value: "The Sun JDK 5 was updated to Update18 to fix various bugs
and security issues.

CVE-2009-1093: LdapCtx in the LDAP service in Java SE
Development Kit (JDK) and Java Runtime Environment (JRE)
5.0 Update 17 and earlier; 6 Update 12 and earlier; SDK and
JRE 1.3.1_24 and earlier; and 1.4.2_19 and earlier does not
close the connection when initialization fails, which
allows remote attackers to cause a denial of service (LDAP
service hang).

CVE-2009-1094: Unspecified vulnerability in the LDAP
implementation in Java SE Development Kit (JDK) and Java
Runtime Environment (JRE) 5.0 Update 17 and earlier; 6
Update 12 and earlier; SDK and JRE 1.3.1_24 and earlier;
and 1.4.2_19 and earlier allows remote LDAP servers to
execute arbitrary code via unknown vectors related to
serialized data.

CVE-2009-1095: Integer overflow in unpack200 in Java SE
Development Kit (JDK) and Java Runtime Environment (JRE)
5.0 Update 17 and earlier, and 6 Update 12 and earlier,
allows remote attackers to access files or execute
arbitrary code via a JAR file with crafted Pack200 headers.

CVE-2009-1096: Buffer overflow in unpack200 in Java SE
Development Kit (JDK) and Java Runtime Environment (JRE)
5.0 Update 17 and earlier, and 6 Update 12 and earlier,
allows remote attackers to access files or execute
arbitrary code via a JAR file with crafted Pack200 headers.

CVE-2009-1098: Buffer overflow in Java SE Development Kit
(JDK) and Java Runtime Environment (JRE) 5.0 Update 17 and
earlier; 6 Update 12 and earlier; 1.4.2_19 and earlier; and
1.3.1_24 and earlier allows remote attackers to access
files or execute arbitrary code via a crafted GIF image,
aka CR 6804998.

CVE-2009-1099: Integer signedness error in Java SE
Development Kit (JDK) and Java Runtime Environment (JRE)
5.0 Update 17 and earlier, and 6 Update 12 and earlier,
allows remote attackers to access files or execute
arbitrary code via a crafted Type1 font, which triggers a
buffer overflow.

CVE-2009-1100: Multiple unspecified vulnerabilities in Java
SE Development Kit (JDK) and Java Runtime Environment (JRE)
5.0 Update 17 and earlier, and 6 Update 12 and earlier,
allow remote attackers to cause a denial of service (disk
consumption) via vectors related to temporary font files
and (1) 'limits on Font creation,' aka CR 6522586, and (2)
another unspecified vector, aka CR 6632886.

CVE-2009-1103: Unspecified vulnerability in the Java
Plug-in in Java SE Development Kit (JDK) and Java Runtime
Environment (JRE) 5.0 Update 17 and earlier; 6 Update 12
and earlier; 1.4.2_19 and earlier; and 1.3.1_24 and earlier
allows remote attackers to access files and execute
arbitrary code via unknown vectors related to
'deserializing applets,' aka CR 6646860.


CVE-2009-1104: The Java Plug-in in Java SE Development Kit
(JDK) and Java Runtime Environment (JRE) 5.0 Update 17 and
earlier; 6 Update 12 and earlier; and 1.4.2_19 and earlier
does not prevent Javascript that is loaded from the
localhost from connecting to other ports on the system,
which allows user-assisted attackers to bypass intended
access restrictions via LiveConnect, aka CR 6724331.  NOTE:
this vulnerability can be leveraged with separate
cross-site scripting (XSS) vulnerabilities for remote
attack vectors.

CVE-2009-1107: The Java Plug-in in Java SE Development Kit
(JDK) and Java Runtime Environment (JRE) 6 Update 12 and
earlier, and 5.0 Update 17 and earlier, allows remote
attackers to trick a user into trusting a signed applet via
unknown vectors that misrepresent the security warning
dialog, related to a 'Swing JLabel HTML parsing
vulnerability,' aka CR 6782871.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for java-1_5_0-sun");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=488926");
script_end_attributes();

 script_cve_id("CVE-2009-1093", "CVE-2009-1094", "CVE-2009-1095", "CVE-2009-1096", "CVE-2009-1098", "CVE-2009-1099", "CVE-2009-1100", "CVE-2009-1103", "CVE-2009-1104", "CVE-2009-1107");
script_summary(english: "Check for the java-1_5_0-sun package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"java-1_5_0-sun-1.5.0_update18-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-1.5.0_update18-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-alsa-1.5.0_update18-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-alsa-1.5.0_update18-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-demo-1.5.0_update18-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-demo-1.5.0_update18-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-devel-1.5.0_update18-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-devel-1.5.0_update18-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-jdbc-1.5.0_update18-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-jdbc-1.5.0_update18-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-plugin-1.5.0_update18-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-src-1.5.0_update18-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-src-1.5.0_update18-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");
