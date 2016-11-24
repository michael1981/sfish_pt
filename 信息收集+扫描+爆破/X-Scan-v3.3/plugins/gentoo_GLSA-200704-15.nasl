# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200704-15.xml
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
 script_id(25060);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200704-15");
 script_cve_id("CVE-2006-7178", "CVE-2006-7179", "CVE-2006-7180");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200704-15 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200704-15
(MadWifi: Multiple vulnerabilities)


    The driver does not properly process Channel Switch Announcement
    Information Elements, allowing for an abnormal channel change. The
    ieee80211_input() function does not properly handle AUTH frames and the
    driver sends unencrypted packets before WPA authentication succeeds.
  
Impact

    A remote attacker could send specially crafted AUTH frames to the
    vulnerable host, resulting in a Denial of Service by crashing the
    kernel. A remote attacker could gain access to sensitive information
    about network architecture by sniffing unencrypted packets. A remote
    attacker could also send a Channel Switch Count less than or equal to
    one to trigger a channel change, resulting in a communication loss and
    a Denial of Service.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All MadWifi users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-wireless/madwifi-ng-0.9.3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-7178');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-7179');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-7180');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200704-15.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200704-15] MadWifi: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'MadWifi: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-wireless/madwifi-ng", unaffected: make_list("ge 0.9.3"), vulnerable: make_list("lt 0.9.3")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
