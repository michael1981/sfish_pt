# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200412-19.xml
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
 script_id(16006);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200412-19");
 script_cve_id("CVE-2004-1147", "CVE-2004-1148");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200412-19 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200412-19
(phpMyAdmin: Multiple vulnerabilities)


    Nicolas Gregoire (exaprobe.com) has discovered two vulnerabilities
    that exist only on a webserver where PHP safe_mode is off. These
    vulnerabilities could lead to command execution or file disclosure.
  
Impact

    On a system where external MIME-based transformations are enabled,
    an attacker can insert offensive values in MySQL, which would start a
    shell when the data is browsed. On a system where the UploadDir is
    enabled, read_dump.php could use the unsanitized sql_localfile variable
    to disclose a file.
  
Workaround

    You can temporarily enable PHP safe_mode or disable external
    MIME-based transformation AND disable the UploadDir. But instead, we
    strongly advise to update your version to 2.6.1_rc1.
  
');
script_set_attribute(attribute:'solution', value: '
    All phpMyAdmin users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-db/phpmyadmin-2.6.1_rc1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-1147');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-1148');
script_set_attribute(attribute: 'see_also', value: 'http://www.phpmyadmin.net/home_page/security.php?issue=PMASA-2004-4');
script_set_attribute(attribute: 'see_also', value: 'http://www.exaprobe.com/labs/advisories/esa-2004-1213.html');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200412-19.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200412-19] phpMyAdmin: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'phpMyAdmin: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-db/phpmyadmin", unaffected: make_list("ge 2.6.1_rc1"), vulnerable: make_list("lt 2.6.1_rc1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
