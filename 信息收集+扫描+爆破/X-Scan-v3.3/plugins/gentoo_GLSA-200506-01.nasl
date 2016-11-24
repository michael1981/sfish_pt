# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200506-01.xml
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
 script_id(18406);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200506-01");
 script_cve_id("CVE-2005-1704");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200506-01 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200506-01
(Binutils, elfutils: Buffer overflow)


    Tavis Ormandy and Ned Ludd of the Gentoo Linux Security Audit Team
    discovered an integer overflow in the BFD library and elfutils,
    resulting in a heap based buffer overflow.
  
Impact

    Successful exploitation would require a user to access a specially
    crafted binary file, resulting in the execution of arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All GNU Binutils users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose sys-devel/binutils
    All elfutils users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-libs/elfutils-0.108"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1704');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200506-01.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200506-01] Binutils, elfutils: Buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Binutils, elfutils: Buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-libs/elfutils", unaffected: make_list("ge 0.108"), vulnerable: make_list("lt 0.108")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "sys-devel/binutils", unaffected: make_list("rge 2.14.90.0.8-r3", "rge 2.15.90.0.1.1-r5", "rge 2.15.90.0.3-r5", "rge 2.15.91.0.2-r2", "rge 2.15.92.0.2-r10", "ge 2.16-r1"), vulnerable: make_list("lt 2.16-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
