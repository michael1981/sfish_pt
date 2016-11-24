# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200506-16.xml
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
 script_id(18531);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200506-16");
 script_cve_id("CVE-2005-1111");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200506-16 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200506-16
(cpio: Directory traversal vulnerability)


    A vulnerability has been found in cpio that can potentially allow
    a cpio archive to extract its files to an arbitrary directory of the
    creator\'s choice.
  
Impact

    An attacker could create a malicious cpio archive which would
    create files in arbitrary locations on the victim\'s system. This issue
    could also be used in conjunction with a previous race condition
    vulnerability (CAN-2005-1111) to change permissions on files owned by
    the victim.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All cpio users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-arch/cpio-2.6-r3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.securityfocus.com/archive/1/396429');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-1111');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200506-16.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200506-16] cpio: Directory traversal vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'cpio: Directory traversal vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-arch/cpio", unaffected: make_list("ge 2.6-r3"), vulnerable: make_list("lt 2.6-r3")
)) { security_note(0); exit(0); }
exit(0, "Host is not affected");
