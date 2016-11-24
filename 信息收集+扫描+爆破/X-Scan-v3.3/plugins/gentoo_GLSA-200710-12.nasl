# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200710-12.xml
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
 script_id(27047);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200710-12");
 script_cve_id("CVE-2007-4033");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200710-12 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200710-12
(T1Lib: Buffer overflow)


    Hamid Ebadi discovered a boundary error in the
    intT1_EnvGetCompletePath() function which can lead to a buffer overflow
    when processing an overly long filename.
  
Impact

    A remote attacker could entice a user to open a font file with a
    specially crafted filename, possibly leading to the execution of
    arbitrary code with the privileges of the user running the application
    using T1Lib.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All T1Lib users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/t1lib-5.0.2-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4033');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200710-12.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200710-12] T1Lib: Buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'T1Lib: Buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-libs/t1lib", unaffected: make_list("ge 5.0.2-r1"), vulnerable: make_list("lt 5.0.2-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
