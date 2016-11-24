# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200404-04.xml
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
 script_id(14469);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200404-04");
 script_cve_id("CVE-2004-0107", "CVE-2004-0108");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200404-04 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200404-04
(Multiple vulnerabilities in sysstat)


    There are two vulnerabilities in the way sysstat handles symlinks:
    The isag utility, which displays sysstat data in a graphical format,
    creates a temporary file in an insecure manner.
    Two scripts in the sysstat package, post and trigger, create temporary
    files in an insecure manner.
  
Impact

    Both vulnerabilities may allow an attacker to overwrite arbitrary files
    under the permissions of the user executing any of the affected
    utilities.
  
Workaround

    A workaround is not currently known for this issue. All users are advised
    to upgrade to the latest version of the affected package.
  
');
script_set_attribute(attribute:'solution', value: '
    Systat users should upgrade to version 4.2 or later:
    # emerge sync
    # emerge -pv ">=app-admin/sysstat-5.0.2"
    # emerge ">=app-admin/sysstat-5.0.2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0107');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0108');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200404-04.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200404-04] Multiple vulnerabilities in sysstat');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Multiple vulnerabilities in sysstat');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-admin/sysstat", arch: "x86 ppc sparc amd64", unaffected: make_list("ge 5.0.2"), vulnerable: make_list("lt 5.0.2")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
