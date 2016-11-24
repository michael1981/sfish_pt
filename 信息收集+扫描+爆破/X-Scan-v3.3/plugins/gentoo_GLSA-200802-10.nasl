# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200802-10.xml
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
 script_id(31158);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200802-10");
 script_cve_id("CVE-2006-7228");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200802-10 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200802-10
(Python: PCRE Integer overflow)


    Python 2.3 includes a copy of PCRE which is vulnerable to an integer
    overflow vulnerability, leading to a buffer overflow.
  
Impact

    An attacker could exploit the vulnerability by tricking a vulnerable
    Python application to compile a regular expressions, which could
    possibly lead to the execution of arbitrary code, a Denial of Service
    or the disclosure of sensitive information.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Python 2.3 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-lang/python-2.3.6-r4"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-7228');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200711-30.xml');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200802-10.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200802-10] Python: PCRE Integer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Python: PCRE Integer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-lang/python", unaffected: make_list("ge 2.3.6-r4"), vulnerable: make_list("lt 2.3.6-r4")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
