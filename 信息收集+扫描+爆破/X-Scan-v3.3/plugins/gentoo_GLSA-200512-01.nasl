# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200512-01.xml
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
 script_id(20280);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200512-01");
 script_cve_id("CVE-2005-3962");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200512-01 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200512-01
(Perl: Format string errors can lead to code execution)


    Jack Louis discovered a new way to exploit format string errors in
    Perl that could lead to the execution of arbitrary code. This is
    perfomed by causing an integer wrap overflow in the efix variable
    inside the function Perl_sv_vcatpvfn. The proposed fix closes that
    specific exploitation vector to mitigate the risk of format string
    programming errors in Perl. This fix does not remove the need to fix
    such errors in Perl code.
  
Impact

    Perl applications making improper use of printf functions (or
    derived functions) using untrusted data may be vulnerable to the
    already-known forms of Perl format string exploits and also to the
    execution of arbitrary code.
  
Workaround

    Fix all misbehaving Perl applications so that they make proper use
    of the printf and derived Perl functions.
  
');
script_set_attribute(attribute:'solution', value: '
    All Perl users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose dev-lang/perl
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3962');
script_set_attribute(attribute: 'see_also', value: 'http://www.dyadsecurity.com/perl-0002.html');
script_set_attribute(attribute: 'see_also', value: 'http://www.securityfocus.com/archive/1/418460/30/30');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200512-01.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200512-01] Perl: Format string errors can lead to code execution');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Perl: Format string errors can lead to code execution');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-lang/perl", unaffected: make_list("ge 5.8.7-r3", "rge 5.8.6-r8"), vulnerable: make_list("lt 5.8.7-r3")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
