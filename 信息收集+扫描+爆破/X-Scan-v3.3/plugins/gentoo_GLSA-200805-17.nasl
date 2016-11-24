# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200805-17.xml
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
 script_id(32415);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200805-17");
 script_cve_id("CVE-2008-1927");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200805-17 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200805-17
(Perl: Execution of arbitrary code)


    Tavis Ormandy and Will Drewry of the Google Security Team have reported
    a double free vulnerability when processing a crafted regular
    expression containing UTF-8 characters.
  
Impact

    A remote attacker could possibly exploit this vulnerability to execute
    arbitrary code or cause a Denial of Service.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Perl users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-lang/perl-5.8.8-r5"
    All libperl users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=sys-devel/libperl-5.8.8-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1927');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200805-17.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200805-17] Perl: Execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Perl: Execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-lang/perl", unaffected: make_list("ge 5.8.8-r5"), vulnerable: make_list("lt 5.8.8-r5")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "sys-devel/libperl", unaffected: make_list("ge 5.8.8-r2"), vulnerable: make_list("lt 5.8.8-r2")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
