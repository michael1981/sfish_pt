# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-05.xml
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
 script_id(16396);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200501-05");
 script_cve_id("CVE-2004-1189");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200501-05 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200501-05
(mit-krb5: Heap overflow in libkadm5srv)


    The MIT Kerberos 5 administration library libkadm5srv contains a
    heap overflow in the code handling password changing.
  
Impact

    Under specific circumstances an attacker could execute arbitary
    code with the permissions of the user running mit-krb5, which could be
    the root user.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All mit-krb5 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-crypt/mit-krb5-1.3.6"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-1189');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200501-05.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200501-05] mit-krb5: Heap overflow in libkadm5srv');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'mit-krb5: Heap overflow in libkadm5srv');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-crypt/mit-krb5", unaffected: make_list("ge 1.3.6"), vulnerable: make_list("lt 1.3.6")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
