# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200802-06.xml
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
 script_id(31084);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200802-06");
 script_cve_id("CVE-2007-6350", "CVE-2007-6415");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200802-06 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200802-06
(scponly: Multiple vulnerabilities)


    Joachim Breitner reported that Subversion and rsync support invokes
    subcommands in an insecure manner (CVE-2007-6350). It has also been
    discovered that scponly does not filter the -o and -F options to the
    scp executable (CVE-2007-6415).
  
Impact

    A local attacker could exploit these vulnerabilities to elevate
    privileges and execute arbitrary commands on the vulnerable host.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All scponly users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/scponly-4.8"
    Due to the design of scponly\'s Subversion support, security
    restrictions can still be circumvented. Please read carefully the
    SECURITY file included in the package.
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6350');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6415');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200802-06.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200802-06] scponly: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'scponly: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/scponly", unaffected: make_list("ge 4.8"), vulnerable: make_list("lt 4.8")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
