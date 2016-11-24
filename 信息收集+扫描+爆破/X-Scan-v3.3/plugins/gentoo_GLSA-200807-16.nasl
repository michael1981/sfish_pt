# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200807-16.xml
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
 script_id(33782);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200807-16");
 script_cve_id("CVE-2008-2315", "CVE-2008-2316", "CVE-2008-3142", "CVE-2008-3143", "CVE-2008-3144");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200807-16 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200807-16
(Python: Multiple vulnerabilities)


    Multiple vulnerabilities were discovered in Python:
    David Remahl of Apple Product Security reported several integer
    overflows in core modules such as stringobject, unicodeobject,
    bufferobject, longobject, tupleobject, stropmodule, gcmodule,
    mmapmodule (CVE-2008-2315).
    David Remahl of Apple Product Security also reported an integer
    overflow in the hashlib module, leading to unreliable cryptographic
    digest results (CVE-2008-2316).
    Justin Ferguson reported multiple buffer overflows in unicode string
    processing that only affect 32bit systems (CVE-2008-3142).
    The Google Security Team reported multiple integer overflows
    (CVE-2008-3143).
    Justin Ferguson reported multiple integer underflows and overflows in
    the PyOS_vsnprintf() function, and an off-by-one error when passing
    zero-length strings, leading to memory corruption (CVE-2008-3144).
  
Impact

    A remote attacker could exploit these vulnerabilities in Python
    applications or daemons that pass user-controlled input to vulnerable
    functions. Exploitation might lead to the execution of arbitrary code
    or a Denial of Service. Vulnerabilities within the hashlib might lead
    to weakened cryptographic protection of data integrity or authenticity.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Python 2.4 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-lang/python-2.4.4-r14"
    All Python 2.5 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-lang/python-2.5.2-r6"
    Please note that Python 2.3 is masked since June 24, and we will not be
    releasing updates to it. It will be removed from the tree in the near
    future.
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2315');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2316');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3142');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3143');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3144');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200807-16.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200807-16] Python: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Python: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-lang/python", unaffected: make_list("rge 2.4.4-r14", "ge 2.5.2-r6", "rge 2.4.6"), vulnerable: make_list("lt 2.5.2-r6")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
