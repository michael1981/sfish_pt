# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200904-12.xml
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
 script_id(36140);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200904-12");
 script_cve_id("CVE-2009-0489");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200904-12 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200904-12
(Wicd: Information disclosure)


    Tiziano Mueller of Gentoo discovered that the DBus configuration file
    for Wicd allows arbitrary users to own the org.wicd.daemon object.
  
Impact

    A local attacker could exploit this vulnerability to receive messages
    that were intended for the Wicd daemon, possibly including credentials
    e.g. for wireless networks.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Wicd users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/wicd-1.5.9"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0489');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200904-12.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200904-12] Wicd: Information disclosure');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Wicd: Information disclosure');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/wicd", unaffected: make_list("ge 1.5.9"), vulnerable: make_list("lt 1.5.9")
)) { security_note(0); exit(0); }
exit(0, "Host is not affected");
