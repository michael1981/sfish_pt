
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29475);
 script_version ("$Revision: 1.9 $");
 script_name(english: "SuSE Security Update:  Security update for IBM Java 1.5.0 (java-1_5_0-ibm-4544)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch java-1_5_0-ibm-4544");
 script_set_attribute(attribute: "description", value: "The IBM Java JRE/SDK has been brought to release 1.5.0
SR5a, containing several bugfixes, including the following
security fixes:

- CVE-2007-2788,CVE-2007-2789,CVE-2007-3004,CVE-2007-3005:
  A buffer overflow vulnerability in the image parsing code
  in the Java(TM) Runtime Environment may allow an
  untrusted applet or application to elevate its
  privileges. For example, an applet may grant itself
  permissions to read and write local files or execute
  local applications that are accessible to the user
  running the untrusted applet.

  A second vulnerability may allow an untrusted applet or
application to cause the Java Virtual Machine to hang.

- CVE-2007-3655: A buffer overflow vulnerability in the
  Java Web Start URL parsing code may allow an untrusted
  application to elevate its privileges. For example, an
  application may grant itself permissions to read and
  write local files or execute local applications with the
  privileges of the user running the Java Web Start
  application.

- CVE-2007-3922: A security vulnerability in the Java
  Runtime Environment Applet Class Loader may allow an
  untrusted applet that is loaded from a remote system to
  circumvent network access restrictions and establish
  socket connections to certain services running on the
  local host, as if it were loaded from the system that the
  applet is running on. This may allow the untrusted remote
  applet the ability to exploit any security
  vulnerabilities existing in the services it has connected
  to.

For more information see:
http://www-128.ibm.com/developerworks/java/jdk/alerts/
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch java-1_5_0-ibm-4544");
script_end_attributes();

 script_cve_id("CVE-2007-2788", "CVE-2007-2789", "CVE-2007-3655", "CVE-2007-3922");
script_summary(english: "Check for the java-1_5_0-ibm-4544 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"java-1_5_0-ibm-1.5.0_sr5a-0.4", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-ibm-alsa-1.5.0_sr5a-0.4", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-ibm-devel-1.5.0_sr5a-0.4", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-ibm-fonts-1.5.0_sr5a-0.4", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-ibm-jdbc-1.5.0_sr5a-0.4", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-ibm-plugin-1.5.0_sr5a-0.4", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-ibm-1.5.0_sr5a-0.4", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-ibm-alsa-1.5.0_sr5a-0.4", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-ibm-demo-1.5.0_sr5a-0.4", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-ibm-devel-1.5.0_sr5a-0.4", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-ibm-jdbc-1.5.0_sr5a-0.4", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-ibm-plugin-1.5.0_sr5a-0.4", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-ibm-src-1.5.0_sr5a-0.4", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
