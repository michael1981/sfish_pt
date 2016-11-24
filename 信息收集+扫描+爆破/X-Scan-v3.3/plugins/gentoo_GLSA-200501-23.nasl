# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-23.xml
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
 script_id(16414);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200501-23");
 script_cve_id("CVE-2005-0021", "CVE-2005-0022");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200501-23 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200501-23
(Exim: Two buffer overflows)


    Buffer overflows have been found in the host_aton() function
    (CAN-2005-0021) as well as in the spa_base64_to_bits() function
    (CAN-2005-0022), which is part of the SPA authentication code.
  
Impact

    A local attacker could trigger the buffer overflow in host_aton()
    by supplying an illegal IPv6 address with more than 8 components, using
    a command line option. The second vulnerability could be remotely
    exploited during SPA authentication, if it is enabled on the server.
    Both buffer overflows can potentially lead to the execution of
    arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Exim users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-mta/exim-4.43-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://www.exim.org/mail-archives/exim-announce/2005/msg00000.html');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0021');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0022');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200501-23.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200501-23] Exim: Two buffer overflows');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Exim: Two buffer overflows');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "mail-mta/exim", unaffected: make_list("ge 4.43-r2"), vulnerable: make_list("lt 4.43-r2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
