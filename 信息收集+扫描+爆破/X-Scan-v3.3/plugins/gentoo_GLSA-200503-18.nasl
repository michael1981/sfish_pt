# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200503-18.xml
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
 script_id(17330);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200503-18");
 script_cve_id("CVE-2004-1292");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200503-18 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200503-18
(Ringtone Tools: Buffer overflow vulnerability)


    Qiao Zhang has discovered a buffer overflow vulnerability in the
    \'parse_emelody\' function in \'parse_emelody.c\'.
  
Impact

    A remote attacker could entice a Ringtone Tools user to open a
    specially crafted eMelody file, which would potentially lead to the
    execution of arbitrary code with the rights of the user running the
    application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Ringtone Tools users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-mobilephone/ringtonetools-2.23"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-1292');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200503-18.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200503-18] Ringtone Tools: Buffer overflow vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Ringtone Tools: Buffer overflow vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-mobilephone/ringtonetools", unaffected: make_list("ge 2.23"), vulnerable: make_list("lt 2.23")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
