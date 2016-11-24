
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-657
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(25863);
 script_version ("$Revision: 1.4 $");
script_name(english: "Fedora 6 2007-657: libgtop2");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-657 (libgtop2)");
 script_set_attribute(attribute: "description", value: "libgtop is a library for portably obtaining information about processes,
such as their PID, memory usage, etc.



Update information :

* Thu Aug  2 2007 Soren Sandmann <sandmann redhat com> - 2.14.9-1
- BuildRequire gtk-doc, package documentation files in devel package
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-0235");
script_summary(english: "Check for the version of the libgtop2 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"libgtop2-2.14.9-1.fc6", release:"FC6") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
