# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200412-25.xml
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
 script_id(16067);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200412-25");
 script_cve_id("CVE-2004-1125", "CVE-2004-1267", "CVE-2004-1268", "CVE-2004-1269", "CVE-2004-1270");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200412-25 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200412-25
(CUPS: Multiple vulnerabilities)


    CUPS makes use of vulnerable Xpdf code to handle PDF files
    (CAN-2004-1125). Furthermore, Ariel Berkman discovered a buffer
    overflow in the ParseCommand function in hpgl-input.c in the hpgltops
    program (CAN-2004-1267). Finally, Bartlomiej Sieka discovered several
    problems in the lppasswd program: it ignores some write errors
    (CAN-2004-1268), it can leave the passwd.new file in place
    (CAN-2004-1269) and it does not verify that passwd.new file is
    different from STDERR (CAN-2004-1270).
  
Impact

    The Xpdf and hpgltops vulnerabilities may be exploited by a remote
    attacker to execute arbitrary code by sending specific print jobs to a
    CUPS spooler. The lppasswd vulnerabilities may be exploited by a local
    attacker to write data to the CUPS password file or deny further
    password modifications.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All CUPS users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-print/cups-1.1.23"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-1125');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-1267');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-1268');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-1269');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-1270');
script_set_attribute(attribute: 'see_also', value: 'http://tigger.uic.edu/~jlongs2/holes/cups.txt');
script_set_attribute(attribute: 'see_also', value: 'http://tigger.uic.edu/~jlongs2/holes/cups2.txt');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200412-25.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200412-25] CUPS: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'CUPS: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-print/cups", unaffected: make_list("ge 1.1.23"), vulnerable: make_list("lt 1.1.23")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
