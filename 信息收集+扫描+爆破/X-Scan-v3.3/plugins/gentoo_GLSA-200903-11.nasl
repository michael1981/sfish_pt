# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200903-11.xml
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
 script_id(35809);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200903-11");
 script_cve_id("CVE-2009-0544");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200903-11 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200903-11
(PyCrypto: Execution of arbitrary code)


    Mike Wiacek of the Google Security Team reported a buffer overflow in
    the ARC2 module when processing a large ARC2 key length.
  
Impact

    A remote attacker could entice a user or automated system to decrypt an
    ARC2 stream in an application using PyCrypto, possibly resulting in the
    execution of arbitrary code or a Denial of Service.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All PyCrypto users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-python/pycrypto-2.0.1-r8"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0544');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200903-11.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200903-11] PyCrypto: Execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PyCrypto: Execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-python/pycrypto", unaffected: make_list("ge 2.0.1-r8"), vulnerable: make_list("lt 2.0.1-r8")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
