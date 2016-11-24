# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200907-08.xml
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
 script_id(39779);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200907-08");
 script_cve_id("CVE-2009-0282");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200907-08 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200907-08
(Multiple Ralink wireless drivers: Execution of arbitrary code)


    Aviv reported an integer overflow in multiple Ralink wireless card
    drivers when processing a probe request packet with a long SSID,
    possibly related to an integer signedness error.
  
Impact

    A physically proximate attacker could send specially crafted packets to
    a user who has wireless networking enabled, possibly resulting in the
    execution of arbitrary code with root privileges.
  
Workaround

    Unload the kernel modules.
  
');
script_set_attribute(attribute:'solution', value: '
    All external kernel modules have been masked and we recommend that
    users unmerge those drivers. The Linux mainline kernel has equivalent
    support for these devices and the vulnerability has been resolved in
    stable versions of sys-kernel/gentoo-sources.
    # emerge --unmerge "net-wireless/rt2400"
    # emerge --unmerge "net-wireless/rt2500"
    # emerge --unmerge "net-wireless/rt2570"
    # emerge --unmerge "net-wireless/rt61"
    # emerge --unmerge "net-wireless/ralink-rt61"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0282');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200907-08.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200907-08] Multiple Ralink wireless drivers: Execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Multiple Ralink wireless drivers: Execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-wireless/ralink-rt61", unaffected: make_list(), vulnerable: make_list("le 1.1.1.0")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "net-wireless/rt2400", unaffected: make_list(), vulnerable: make_list("le 1.2.2_beta3")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "net-wireless/rt2570", unaffected: make_list(), vulnerable: make_list("le 20070209")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "net-wireless/rt61", unaffected: make_list(), vulnerable: make_list("le 1.1.0_beta2")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "net-wireless/rt2500", unaffected: make_list(), vulnerable: make_list("le 1.1.0_pre2007071515")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
