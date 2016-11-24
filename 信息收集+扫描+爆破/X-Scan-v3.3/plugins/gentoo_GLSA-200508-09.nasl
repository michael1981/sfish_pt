# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200508-09.xml
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
 script_id(19442);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200508-09");
 script_cve_id("CVE-2005-2547");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200508-09 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200508-09
(bluez-utils: Bluetooth device name validation vulnerability)


    The name of a Bluetooth device is improperly validated by the hcid
    utility when a remote device attempts to pair itself with a computer.
  
Impact

    An attacker could create a malicious device name on a Bluetooth
    device resulting in arbitrary commands being executed as root upon
    attempting to pair the device with the computer.
  
Workaround

    There are no known workarounds at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All bluez-utils users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-wireless/bluez-utils-2.19"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-2547');
script_set_attribute(attribute: 'see_also', value: 'http://cvs.sourceforge.net/viewcvs.py/bluez/utils/ChangeLog?rev=1.28&view=markup');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200508-09.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200508-09] bluez-utils: Bluetooth device name validation vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'bluez-utils: Bluetooth device name validation vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-wireless/bluez-utils", unaffected: make_list("ge 2.19"), vulnerable: make_list("lt 2.19")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
