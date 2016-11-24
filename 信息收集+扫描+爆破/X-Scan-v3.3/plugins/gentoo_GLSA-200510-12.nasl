# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200510-12.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description)
{
 script_id(20032);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200510-12");
 script_cve_id("CVE-2005-2971");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200510-12 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200510-12
(KOffice, KWord: RTF import buffer overflow)


    Chris Evans discovered that the KWord RTF importer was vulnerable
    to a heap-based buffer overflow.
  
Impact

    An attacker could entice a user to open a specially-crafted RTF
    file, potentially resulting in the execution of arbitrary code with the
    rights of the user running the affected application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All KOffice users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-office/koffice-1.4.1-r1"
    All KWord users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-office/kword-1.4.1-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=2005-2971');
script_set_attribute(attribute: 'see_also', value: 'http://www.kde.org/info/security/advisory-20051011-1.txt');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200510-12.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200510-12] KOffice, KWord: RTF import buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'KOffice, KWord: RTF import buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-office/kword", unaffected: make_list("ge 1.4.1-r1"), vulnerable: make_list("lt 1.4.1-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "app-office/koffice", unaffected: make_list("ge 1.4.1-r1"), vulnerable: make_list("lt 1.4.1-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
