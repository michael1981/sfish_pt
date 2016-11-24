# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-21.xml
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
 script_id(16412);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200501-21");
 script_cve_id("CVE-2004-1182");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200501-21 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200501-21
(HylaFAX: hfaxd unauthorized login vulnerability)


    The code used by hfaxd to match a given username and hostname with
    an entry in the hosts.hfaxd file is insufficiently protected against
    malicious entries.
  
Impact

    If the HylaFAX installation uses a weak hosts.hfaxd file, a remote
    attacker could authenticate using a malicious username or hostname and
    bypass the intended access restrictions.
  
Workaround

    As a workaround, administrators may consider adding passwords to
    all entries in the hosts.hfaxd file.
  
');
script_set_attribute(attribute:'solution', value: '
    All HylaFAX users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/hylafax-4.2.0-r2"
    Note: Due to heightened security, weak entries in the
    hosts.hfaxd file may no longer work. Please see the HylaFAX
    documentation for details of accepted syntax in the hosts.hfaxd file.
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-1182');
script_set_attribute(attribute: 'see_also', value: 'http://marc.theaimsgroup.com/?l=hylafax&m=110545119911558&w=2');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200501-21.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200501-21] HylaFAX: hfaxd unauthorized login vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'HylaFAX: hfaxd unauthorized login vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/hylafax", unaffected: make_list("ge 4.2.0-r2"), vulnerable: make_list("lt 4.2.0-r2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
