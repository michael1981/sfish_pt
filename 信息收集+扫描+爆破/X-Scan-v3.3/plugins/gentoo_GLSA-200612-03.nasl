# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200612-03.xml
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
 script_id(23855);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200612-03");
 script_cve_id("CVE-2006-6169", "CVE-2006-6235");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200612-03 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200612-03
(GnuPG: Multiple vulnerabilities)


    Hugh Warrington has reported a boundary error in GnuPG, in the
    "ask_outfile_name()" function from openfile.c: the
    make_printable_string() function could return a string longer than
    expected. Additionally, Tavis Ormandy of the Gentoo Security Team
    reported a design error in which a function pointer can be incorrectly
    dereferenced.
  
Impact

    A remote attacker could entice a user to interactively use GnuPG on a
    crafted file and trigger the boundary error, which will result in a
    buffer overflow. They could also entice a user to process a signed or
    encrypted file with gpg or gpgv, possibly called through another
    application like a mail client, to trigger the dereference error. Both
    of these vulnerabilities would result in the execution of arbitrary
    code with the permissions of the user running GnuPG. gpg-agent, gpgsm
    and other tools are not affected.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All GnuPG users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose "=app-crypt/gnupg-1.4*"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-6169');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-6235');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200612-03.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200612-03] GnuPG: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'GnuPG: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-crypt/gnupg", unaffected: make_list("ge 1.4.6"), vulnerable: make_list("lt 1.4.6")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
