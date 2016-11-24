
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2006-1468
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24075);
 script_version ("$Revision: 1.4 $");
script_name(english: "Fedora 6 2006-1468: gdm");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2006-1468 (gdm)");
 script_set_attribute(attribute: "description", value: "Gdm (the GNOME Display Manager) is a highly configurable
reimplementation of xdm, the X Display Manager. Gdm allows you to log
into your system with the X Window System running and supports running
several different X sessions on your local machine at the same time.

Update Information:

This update brings gdm to the latest stable upstream version,
which among other bug fixes and improvements contains a
fix for a recently reported security issue that has ID
CVE-2006-6105. This fixes a problem where a user can
enter strings like '%08x' into the gdmchooser 'Add'j
host button and print out memory.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:S/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2006-2452", "CVE-2006-6105");
script_summary(english: "Check for the version of the gdm package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"gdm-2.16.4-1.fc6", release:"FC6") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
