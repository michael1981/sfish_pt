# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200603-15.xml
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
 script_id(21096);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200603-15");
 script_cve_id("CVE-2006-0898");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200603-15 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200603-15
(Crypt::CBC: Insecure initialization vector)


    Lincoln Stein discovered that Crypt::CBC fails to handle 16 bytes
    long initializiation vectors correctly when running in the RandomIV
    mode, resulting in a weaker encryption because the second part of every
    block will always be encrypted with zeros if the blocksize of the
    cipher is greater than 8 bytes.
  
Impact

    An attacker could exploit weak ciphertext produced by Crypt::CBC
    to bypass certain security restrictions or to gain access to sensitive
    data.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Crypt::CBC users should upgrade to the latest available
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-perl/crypt-cbc-2.17"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0898');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200603-15.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200603-15] Crypt::CBC: Insecure initialization vector');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Crypt::CBC: Insecure initialization vector');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-perl/crypt-cbc", unaffected: make_list("ge 2.17"), vulnerable: make_list("lt 2.17")
)) { security_note(0); exit(0); }
exit(0, "Host is not affected");
