# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200704-23.xml
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
 script_id(25111);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200704-23");
 script_cve_id("CVE-2007-1217");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200704-23 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200704-23
(capi4k-utils: Buffer overflow)


    The bufprint() function in capi4k-utils fails to properly check
    boundaries of data coming from CAPI packets.
  
Impact

    A local attacker could possibly escalate privileges or cause a Denial
    of Service by sending a crafted CAPI packet.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All capi4k-utils users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-dialup/capi4k-utils-20050718-r3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=2007-1217');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200704-23.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200704-23] capi4k-utils: Buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'capi4k-utils: Buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-dialup/capi4k-utils", unaffected: make_list("ge 20050718-r3"), vulnerable: make_list("lt 20050718-r3")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
