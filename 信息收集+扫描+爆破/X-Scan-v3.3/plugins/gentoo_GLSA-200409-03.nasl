# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-03.xml
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
 script_id(14650);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200409-03");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200409-03 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200409-03
(Python 2.2: Buffer overflow in getaddrinfo())


    If IPV6 is disabled in Python 2.2, getaddrinfo() is not able to handle IPV6
    DNS requests properly and a buffer overflow occurs.
  
Impact

    An attacker can execute arbitrary code as the user running python.
  
Workaround

    Users with IPV6 enabled are not affected by this vulnerability.
  
');
script_set_attribute(attribute:'solution', value: '
    All Python 2.2 users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=dev-lang/python-2.2.2"
    # emerge ">=dev-lang/python-2.2.2"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0150');
script_set_attribute(attribute: 'see_also', value: 'http://www.osvdb.org/4172');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200409-03.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200409-03] Python 2.2: Buffer overflow in getaddrinfo()');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Python 2.2: Buffer overflow in getaddrinfo()');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-lang/python", unaffected: make_list("ge 2.2.2", "lt 2.2"), vulnerable: make_list("lt 2.2.2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
