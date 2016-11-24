# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200504-09.xml
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
 script_id(18031);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200504-09");
 script_cve_id("CVE-2005-0390");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200504-09 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200504-09
(Axel: Vulnerability in HTTP redirection handling)


    A possible buffer overflow has been reported in the HTTP
    redirection handling code in conn.c.
  
Impact

    A remote attacker could exploit this vulnerability by setting up a
    malicious site and enticing a user to connect to it. This could
    possibly lead to the execution of arbitrary code with the permissions
    of the user running Axel.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Axel users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/axel-1.0b"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0390');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200504-09.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200504-09] Axel: Vulnerability in HTTP redirection handling');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Axel: Vulnerability in HTTP redirection handling');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/axel", unaffected: make_list("ge 1.0b"), vulnerable: make_list("lt 1.0b")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
