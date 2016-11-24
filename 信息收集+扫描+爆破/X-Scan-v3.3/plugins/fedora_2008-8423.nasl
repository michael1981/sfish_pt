
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-8423
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(34314);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2008-8423: emacspeak");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-8423 (emacspeak)");
 script_set_attribute(attribute: "description", value: "Emacspeak is a speech interface that allows visually impaired users to
interact independently and efficiently with the computer. Emacspeak has
dramatically changed how the author and hundreds of blind and visually
impaired users around the world interact with the personal computer and
the Internet. A rich suite of task-oriented speech-enabled tools provides
efficient speech-enabled access to the evolving semantic WWW.
When combined with Linux running on low-cost PC hardware,
Emacspeak/Linux provides a reliable, stable speech-friendly solution that
opens up the Internet to visually impaired users around the world.

-
ChangeLog:


Update information :

* Fri Sep 26 2008 Jens Petersen <petersen redhat com> - 28.0-3
- (CVE-2008-4191) fix tmpfile vulnerability in extract-table.pl with
emacspeak-28.0-tmpfile.patch from upstream svn (#463819)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-4191");
script_summary(english: "Check for the version of the emacspeak package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"emacspeak-28.0-3.fc8", release:"FC8") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
