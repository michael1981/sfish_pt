# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-42.xml
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
 script_id(16433);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200501-42");
 script_cve_id("CVE-2005-0071");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200501-42 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200501-42
(VDR: Arbitrary file overwriting issue)


    Javier Fernandez-Sanguino Pena from the Debian Security Audit Team
    discovered that VDR accesses user-controlled files insecurely.
  
Impact

    A local attacker could create malicious links and invoke a VDR
    recording that would overwrite arbitrary files on the system.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All VDR users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-video/vdr-1.2.6-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0071');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200501-42.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200501-42] VDR: Arbitrary file overwriting issue');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'VDR: Arbitrary file overwriting issue');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-video/vdr", unaffected: make_list("ge 1.2.6-r1"), vulnerable: make_list("lt 1.2.6-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
