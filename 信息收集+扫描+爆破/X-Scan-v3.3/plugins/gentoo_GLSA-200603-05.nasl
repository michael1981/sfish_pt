# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200603-05.xml
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
 script_id(21022);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200603-05");
 script_cve_id("CVE-2006-0855");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200603-05 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200603-05
(zoo: Stack-based buffer overflow)


    Jean-Sebastien Guay-Leroux discovered a boundary error in the
    fullpath() function in misc.c when processing overly long file and
    directory names in ZOO archives.
  
Impact

    An attacker could craft a malicious ZOO archive and entice someone
    to open it using zoo. This would trigger a stack-based buffer overflow
    and potentially allow execution of arbitrary code with the rights of
    the victim user.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All zoo users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-arch/zoo-2.10-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0855');
script_set_attribute(attribute: 'see_also', value: 'http://www.guay-leroux.com/projects/zoo-advisory.txt');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200603-05.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200603-05] zoo: Stack-based buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'zoo: Stack-based buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-arch/zoo", unaffected: make_list("ge 2.10-r1"), vulnerable: make_list("lt 2.10-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
