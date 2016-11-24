# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200706-04.xml
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
 script_id(25474);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200706-04");
 script_cve_id("CVE-2007-2829", "CVE-2007-2830", "CVE-2007-2831");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200706-04 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200706-04
(MadWifi: Multiple vulnerabilities)


    Md Sohail Ahmad from AirTight Networks has discovered a divison by zero
    in the ath_beacon_config() function (CVE-2007-2830). The vendor has
    corrected an input validation error in the
    ieee80211_ioctl_getwmmparams() and ieee80211_ioctl_getwmmparams()
    functions(CVE-207-2831), and an input sanitization error when parsing
    nested 802.3 Ethernet frame lengths (CVE-2007-2829).
  
Impact

    An attacker could send specially crafted packets to a vulnerable host
    to exploit one of these vulnerabilities, possibly resulting in the
    execution of arbitrary code with root privileges, or a Denial of
    Service.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All MadWifi users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-wireless/madwifi-ng-0.9.3.1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-2829');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-2830');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-2831');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200706-04.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200706-04] MadWifi: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'MadWifi: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-wireless/madwifi-ng", unaffected: make_list("ge 0.9.3.1"), vulnerable: make_list("lt 0.9.3.1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
