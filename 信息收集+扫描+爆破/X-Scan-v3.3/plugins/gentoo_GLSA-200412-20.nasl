# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200412-20.xml
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
 script_id(16010);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200412-20");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200412-20 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200412-20
(NASM: Buffer overflow vulnerability)


    Jonathan Rockway discovered that NASM-0.98.38 has an unprotected
    vsprintf() to an array in preproc.c. This code vulnerability may lead
    to a buffer overflow and potential execution of arbitrary code.
  
Impact

    A remote attacker could craft a malicious object file which, when
    supplied in NASM, would result in the execution of arbitrary code with
    the rights of the user running NASM.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All NASM users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-lang/nasm-0.98.38-r1"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://sourceforge.net/mailarchive/forum.php?thread_id=6166881&forum_id=4978');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200412-20.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200412-20] NASM: Buffer overflow vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'NASM: Buffer overflow vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-lang/nasm", unaffected: make_list("ge 0.98.38-r1"), vulnerable: make_list("le 0.98.38")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
