
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-6465
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(39407);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 11 2009-6465: mutt");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-6465 (mutt)");
 script_set_attribute(attribute: "description", value: "Mutt is a small but very powerful text-based MIME mail client.  Mutt
is highly configurable, and is well suited to the mail power user with
advanced features like key bindings, keyboard macros, mail threading,
regular expression searches and a powerful pattern matching language
for selecting groups of messages.

-
Update Information:

This update fixes a problem with SSL certificate chain verification
(CVE-2009-1390).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-1390");
script_summary(english: "Check for the version of the mutt package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"mutt-1.5.19-5.fc11", release:"FC11") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
