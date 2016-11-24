# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200606-26.xml
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
 script_id(21759);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200606-26");
 script_cve_id("CVE-2006-3293");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200606-26 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200606-26
(EnergyMech: Denial of Service)


    A bug in EnergyMech fails to handle empty CTCP NOTICEs correctly, and
    will cause a crash from a segmentation fault.
  
Impact

    By sending an empty CTCP NOTICE, a remote attacker could exploit this
    vulnerability to cause a Denial of Service.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All EnergyMech users should update to the latest stable version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-irc/emech-3.0.2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.energymech.net/versions-3.0.html');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3293');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200606-26.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200606-26] EnergyMech: Denial of Service');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'EnergyMech: Denial of Service');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-irc/emech", unaffected: make_list("ge 3.0.2"), vulnerable: make_list("lt 3.0.2")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
