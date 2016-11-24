# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200808-05.xml
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
 script_id(33835);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200808-05");
 script_cve_id("CVE-2007-0062");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200808-05 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200808-05
(ISC DHCP: Denial of Service)


    A buffer overflow error was found in ISC DHCP server, that can only be
    exploited under unusual server configurations where the DHCP server is
    configured to provide clients with a large set of DHCP options.
  
Impact

    A remote attacker could exploit this vulnerability to cause a Denial of
    Service.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All ISC DHCP users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/dhcp-3.1.1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0062');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200808-05.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200808-05] ISC DHCP: Denial of Service');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ISC DHCP: Denial of Service');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/dhcp", unaffected: make_list("ge 3.1.1"), vulnerable: make_list("lt 3.1.1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
