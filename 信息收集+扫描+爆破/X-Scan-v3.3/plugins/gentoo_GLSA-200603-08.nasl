# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200603-08.xml
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
 script_id(21046);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200603-08");
 script_cve_id("CVE-2006-0049");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200603-08 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200603-08
(GnuPG: Incorrect signature verification)


    OpenPGP is the standard that defines the format of digital
    signatures supported by GnuPG. OpenPGP signatures consist of multiple
    sections, in a strictly defined order. Tavis Ormandy of the Gentoo
    Linux Security Audit Team discovered that certain illegal signature
    formats could allow signed data to be modified without detection. GnuPG
    has previously attempted to be lenient when processing malformed or
    legacy signature formats, but this has now been found to be insecure.
  
Impact

    A remote attacker may be able to construct or modify a
    digitally-signed message, potentially allowing them to bypass
    authentication systems, or impersonate another user.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All GnuPG users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-crypt/gnupg-1.4.2.2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0049');
script_set_attribute(attribute: 'see_also', value: 'http://lists.gnupg.org/pipermail/gnupg-announce/2006q1/000216.html');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200603-08.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200603-08] GnuPG: Incorrect signature verification');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'GnuPG: Incorrect signature verification');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-crypt/gnupg", unaffected: make_list("ge 1.4.2.2"), vulnerable: make_list("lt 1.4.2.2")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
