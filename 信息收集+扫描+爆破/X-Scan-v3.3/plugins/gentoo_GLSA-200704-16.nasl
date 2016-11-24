# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200704-16.xml
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
 script_id(25104);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200704-16");
 script_cve_id("CVE-2007-2057");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200704-16 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200704-16
(Aircrack-ng: Remote execution of arbitrary code)


    Jonathan So reported that the airodump-ng module does not correctly
    check the size of 802.11 authentication packets before copying them
    into a buffer.
  
Impact

    A remote attacker could trigger a stack-based buffer overflow by
    sending a specially crafted 802.11 authentication packet to a user
    running airodump-ng with the -w (--write) option. This could lead to
    the remote execution of arbitrary code with the permissions of the user
    running airodump-ng, which is typically the root user.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Aircrack-ng users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-wireless/aircrack-ng-0.7-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-2057');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200704-16.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200704-16] Aircrack-ng: Remote execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Aircrack-ng: Remote execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-wireless/aircrack-ng", unaffected: make_list("ge 0.7-r2"), vulnerable: make_list("lt 0.7-r2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
