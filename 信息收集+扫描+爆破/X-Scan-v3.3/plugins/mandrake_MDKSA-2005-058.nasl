
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17346);
 script_version ("$Revision: 1.5 $");
 script_name(english: "MDKSA-2005:058: kdelibs");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:058 (kdelibs).");
 script_set_attribute(attribute: "description", value: "A vulnerability in dcopserver was discovered by Sebastian Krahmer of
the SUSE security team. A local user can lock up the dcopserver of
other users on the same machine by stalling the DCOP authentication
process, causing a local Denial of Service. dcopserver is the KDE
Desktop Communication Procotol daemon (CVE-2005-0396).
As well, the IDN (International Domain Names) support in Konqueror is
vulnerable to a phishing technique known as a Homograph attack. This
attack is made possible due to IDN allowing a website to use a wide
range of international characters that have a strong resemblance to
other characters. This can be used to trick users into thinking they
are on a different trusted site when they are in fact on a site mocked
up to look legitimate using these other characters, known as
homographs. This can be used to trick users into providing personal
information to a site they think is trusted (CVE-2005-0237).
Finally, it was found that the dcopidlng script was vulnerable to
symlink attacks, potentially allowing a local user to overwrite
arbitrary files of a user when the script is run on behalf of that
user. However, this script is only used as part of the build process
of KDE itself and may also be used by the build processes of third-
party KDE applications (CVE-2005-0365).
The updated packages are patched to deal with these issues and
Mandrakesoft encourages all users to upgrade immediately.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:058");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-0237", "CVE-2005-0365", "CVE-2005-0396");
script_summary(english: "Check for the version of the kdelibs package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"kdelibs-common-3.2-36.12.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libkdecore4-3.2-36.12.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libkdecore4-devel-3.2-36.12.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdelibs-common-3.2.3-104.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libkdecore4-3.2.3-104.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libkdecore4-devel-3.2.3-104.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"kdelibs-", release:"MDK10.0")
 || rpm_exists(rpm:"kdelibs-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2005-0237", value:TRUE);
 set_kb_item(name:"CVE-2005-0365", value:TRUE);
 set_kb_item(name:"CVE-2005-0396", value:TRUE);
}
exit(0, "Host is not affected");
