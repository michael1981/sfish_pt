# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200411-27.xml
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
 script_id(15768);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200411-27");
 script_cve_id("CVE-2004-1030", "CVE-2004-1031", "CVE-2004-1032", "CVE-2004-1033");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200411-27 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200411-27
(Fcron: Multiple vulnerabilities)


    Due to design errors in the fcronsighup program, Fcron may allow a
    local user to bypass access restrictions (CAN-2004-1031), view the
    contents of root owned files (CAN-2004-1030), remove arbitrary files or
    create empty files (CAN-2004-1032), and send a SIGHUP to any process. A
    vulnerability also exists in fcrontab which may allow local users to
    view the contents of fcron.allow and fcron.deny (CAN-2004-1033).
  
Impact

    A local attacker could exploit these vulnerabilities to perform a
    Denial of Service on the system running Fcron.
  
Workaround

    Make sure the fcronsighup and fcrontab binaries are only
    executable by trusted users.
  
');
script_set_attribute(attribute:'solution', value: '
    All Fcron users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=sys-process/fcron-2.0.2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-1030');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-1031');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-1032');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-1033');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200411-27.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200411-27] Fcron: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Fcron: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "sys-process/fcron", unaffected: make_list("rge 2.0.2", "ge 2.9.5.1"), vulnerable: make_list("le 2.9.5")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
