# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200406-19.xml
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
 script_id(14530);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200406-19");
 script_cve_id("CVE-2004-0604");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200406-19 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200406-19
(giFT-FastTrack: remote denial of service attack)


    Alan Fitton found a vulnerability in the giFT-FastTrack plugin in
    version 0.8.6 and earlier. It can be used to remotely crash the giFT
    daemon.
  
Impact

    Attackers may use this vulnerability to perform a Denial of Service
    attack against the giFT daemon. There is no risk of code execution.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version.
  
');
script_set_attribute(attribute:'solution', value: '
    All users should upgrade to the latest available version of
    gift-fasttrack:
    # emerge sync
    # emerge -pv ">=net-p2p/gift-fasttrack-0.8.7"
    # emerge ">=net-p2p/gift-fasttrack-0.8.7"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://gift-fasttrack.berlios.de/');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0604');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200406-19.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200406-19] giFT-FastTrack: remote denial of service attack');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'giFT-FastTrack: remote denial of service attack');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-p2p/gift-fasttrack", unaffected: make_list("ge 0.8.7"), vulnerable: make_list("le 0.8.6")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
