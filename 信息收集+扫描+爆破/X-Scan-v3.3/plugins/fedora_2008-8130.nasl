
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-8130
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(34227);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2008-8130: tomcat5");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-8130 (tomcat5)");
 script_set_attribute(attribute: "description", value: "Tomcat is the servlet container that is used in the official Reference
Implementation for the Java Servlet and JavaServer Pages technologies.
The Java Servlet and JavaServer Pages specifications are developed by
Sun under the Java Community Process.

Tomcat is developed in an open and participatory environment and
released under the Apache Software License. Tomcat is intended to be
a collaboration of the best-of-breed developers from around the world.
We invite you to participate in this open development project. To
learn more about getting involved, click here.

-
ChangeLog:


Update information :

* Mon Sep 15 2008 David Walluck <dwalluck redhat com> 0:5.5.27-0jpp.2
- add commons-io symlink
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-1355", "CVE-2007-1358", "CVE-2007-2449", "CVE-2007-2450", "CVE-2007-3382", "CVE-2007-3385", "CVE-2007-3386", "CVE-2007-5333", "CVE-2007-5342", "CVE-2007-5461", "CVE-2007-6286", "CVE-2008-1232", "CVE-2008-1947", "CVE-2008-2370", "CVE-2008-2938");
script_summary(english: "Check for the version of the tomcat5 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"tomcat5-5.5.27-0jpp.2.fc8", release:"FC8") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
