# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200903-29.xml
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
 script_id(35942);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200903-29");
 script_cve_id("CVE-2008-2374");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200903-29 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200903-29
(BlueZ: Arbitrary code execution)


    It has been reported that the Bluetooth packet parser does not validate
    string length fields in SDP packets.
  
Impact

    A physically proximate attacker using a Bluetooth device with an
    already established trust relationship could send specially crafted
    requests, possibly leading to arbitrary code execution or a crash.
    Exploitation may also be triggered by a local attacker registering a
    service record via a UNIX socket or D-Bus interface.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All bluez-utils users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-wireless/bluez-utils-3.36"
    All bluez-libs users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-wireless/bluez-libs-3.36"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2374');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200903-29.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200903-29] BlueZ: Arbitrary code execution');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'BlueZ: Arbitrary code execution');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-wireless/bluez-libs", unaffected: make_list("ge 3.36"), vulnerable: make_list("lt 3.36")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "net-wireless/bluez-utils", unaffected: make_list("ge 3.36"), vulnerable: make_list("lt 3.36")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
