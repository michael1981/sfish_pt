
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2006-487
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24087);
 script_version ("$Revision: 1.4 $");
script_name(english: "Fedora 5 2006-487: mozilla");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2006-487 (mozilla)");
 script_set_attribute(attribute: "description", value: "Mozilla is an open-source web browser, designed for standards
compliance, performance and portability.

Update Information:

Updated mozilla packages that fix several security bugs are
now available.

This update has been rated as having critical security
impact by the Fedora Security Response Team.

Mozilla is an open source Web browser, advanced email and
newsgroup client, IRC chat client, and HTML editor.

Several bugs were found in the way Mozilla processes
malformed JavaScript. A malicious web page could modify the
content of a different open web page, possibly stealing
sensitive information or conducting a cross-site scripting
attack. (CVE-2006-1731, CVE-2006-1732, CVE-2006-1741)

Several bugs were found in the way Mozilla processes certain
JavaScript actions. A malicious web page could execute
arbitrary JavaScript instructions with the permissions of
'chrome', allowing the page to steal sensitive information
or install browser malware. (CVE-2006-1727, CVE-2006-1728,
CVE-2006-1733, CVE-2006-1734, CVE-2006-1735, CVE-2006-1742)

Several bugs were found in the way Mozilla processes
malformed web pages. A carefully crafted malicious web page
could cause the execution of arbitrary code as the user
running Mozilla. (CVE-2006-0748, CVE-2006-0749,
CVE-2006-1730, CVE-2006-1737, CVE-2006-1738, CVE-2006-1739,
CVE-2006-1790)

A bug was found in the way Mozilla displays the secure site
icon. If a browser is configured to display the non-default
secure site modal warning dialog, it may be possible to
trick a user into believing they are viewing a secure site.
(CVE-2006-1740)

A bug was found in the way Mozilla allows JavaScript
mutation events on 'input' form elements. A malicious web
page could be created in such a way that when a user submits
a form, an arbitrary file could be uploaded to the attacker.
(CVE-2006-1729)

A bug was found in the way Mozilla executes in-line mail
forwarding. If a user can be tricked into forwarding a
maliciously crafted mail message as in-line content, it is
possible for the message to execute JavaScript with the
permissions of 'chrome'. (CVE-2006-0884)

Users of Mozilla are advised to upgrade to these updated
packages containing Mozilla version 1.7.13 which corrects
these issues.

");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2006-0749", "CVE-2006-0884", "CVE-2006-1728", "CVE-2006-1729", "CVE-2006-1739", "CVE-2006-1740", "CVE-2006-1741", "CVE-2006-1742", "CVE-2006-1790");
script_summary(english: "Check for the version of the mozilla package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"mozilla-1.7.13-1.1.fc5", release:"FC5") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
