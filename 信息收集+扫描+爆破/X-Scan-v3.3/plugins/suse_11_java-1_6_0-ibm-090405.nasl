
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41405);
 script_version("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  java-1_6_0-ibm (2009-04-05)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for java-1_6_0-ibm");
 script_set_attribute(attribute: "description", value: "This update brings the IBM Java 6 JDK and JRE to Service
Release 4. It fixes lots of bugs and various security
issues:

CVE-2008-5341: A vulnerability in the Java Runtime
Environment may allow an untrusted Java Web Start
application to determine the location of the Java Web Start
cache and the username of the user running the Java Web
Start application.

CVE-2008-5340: A vulnerability in the Java Runtime
Environment with launching Java Web Start applications may
allow an untrusted Java Web Start application to escalate
privileges. For example, an untrusted application may grant
itself permissions to read and write local files or execute
local applications that are accessible to the user running
the untrusted application.

CVE-2008-5351: The UTF-8 (Unicode Transformation Format-8)
decoder in the Java Runtime Environment (JRE) accepts
encodings that are longer than the 'shortest' form. This
behavior is not a vulnerability in Java SE. However, it may
be leveraged to exploit systems running software that
relies on the JRE UTF-8 decoder to reject non-shortest form
sequences. For example, non-shortest form sequences may be
decoded into illegal URIs, which may then allow files that
are not otherwise accessible to be read, if the URIs are
not checked following UTF-8 decoding.

CVE-2008-5356: A buffer vulnerability in the Java Runtime
Environment (JRE) with processing fonts may allow an
untrusted applet or Java Web Start application to escalate
privileges. For example, an untrusted applet may grant
itself permissions to read and write local files or execute
local applications that are accessible to the user running
the untrusted applet.

CVE-2008-5357: A buffer vulnerability in the Java Runtime
Environment (JRE) with processing fonts may allow an
untrusted applet or Java Web Start application to escalate
privileges. For example, an untrusted applet may grant
itself permissions to read and write local files or execute
local applications that are accessible to the user running
the untrusted applet.

CVE-2008-5358: A buffer overflow vulnerability in the Java
Runtime Environment with processing GIF images may allow an
untrusted Java Web Start application to escalate
privileges. For example, an untrusted application may grant
itself permissions to read and write local files or execute
local applications that are accessible to the user running
the untrusted applet.

CVE-2008-5342: A security vulnerability in the the Java Web
Start BasicService allows untrusted applications that are
downloaded from another system to request local files to be
displayed by the browser of the user running the untrusted
application.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for java-1_6_0-ibm");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=489052");
script_end_attributes();

 script_cve_id("CVE-2008-5340", "CVE-2008-5341", "CVE-2008-5342", "CVE-2008-5351", "CVE-2008-5356", "CVE-2008-5357", "CVE-2008-5358");
script_summary(english: "Check for the java-1_6_0-ibm package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"java-1_6_0-ibm-1.6.0-124.6.1", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-ibm-alsa-1.6.0-124.6.1", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-ibm-fonts-1.6.0-124.6.1", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-ibm-jdbc-1.6.0-124.6.1", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-ibm-plugin-1.6.0-124.6.1", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
