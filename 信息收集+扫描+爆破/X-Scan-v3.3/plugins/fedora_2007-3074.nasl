
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-3074
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(28160);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2007-3074: inotify-tools");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-3074 (inotify-tools)");
 script_set_attribute(attribute: "description", value: "inotify-tools is a set of command-line programs for Linux providing
a simple interface to inotify. These programs can be used to monitor
and act upon filesystem events.

-
Update Information:

A vulnerability has been reported in inotify-tools, which can potentially be
exploited by malicious users to compromise an application using the library.

Successful exploitation may allow the execution of arbitrary code with
privileges of the application using the affected library.

NOTE: The programs shipped with inotify-tools are reportedly not affected.

The vulnerability is reported in versions prior to 3.11.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-5037");
script_summary(english: "Check for the version of the inotify-tools package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"inotify-tools-3.11-1.fc7", release:"FC7") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
