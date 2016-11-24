# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200608-27.xml
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
 script_id(22289);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200608-27");
 script_cve_id("CVE-2005-3863");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200608-27 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200608-27
(Motor: Execution of arbitrary code)


    In November 2005, Zone-H Research reported a boundary error in the
    ktools library in the VGETSTRING() macro of kkstrtext.h, which may
    cause a buffer overflow via an overly long input string.
  
Impact

    A remote attacker could entice a user to use a malicious file or input,
    which could lead to the crash of Motor and possibly the execution of
    arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Motor 3.3.x users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-util/motor-3.3.0-r1"
    All motor 3.4.x users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-util/motor-3.4.0-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3863');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200608-27.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200608-27] Motor: Execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Motor: Execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-util/motor", unaffected: make_list("rge 3.3.0-r1", "ge 3.4.0-r1"), vulnerable: make_list("lt 3.4.0-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
