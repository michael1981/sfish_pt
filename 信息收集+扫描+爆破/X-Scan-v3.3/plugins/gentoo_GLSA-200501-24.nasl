# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-24.xml
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
 script_id(16415);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200501-24");
 script_cve_id("CVE-2004-1294");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200501-24 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200501-24
(tnftp: Arbitrary file overwriting)


    The \'mget\' function in cmds.c lacks validation of the filenames
    that are supplied by the server.
  
Impact

    An attacker running an FTP server could supply clients with
    malicious filenames, potentially allowing the overwriting of arbitrary
    files with the permission of the connected user.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All tnftp users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-ftp/tnftp-20050103"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-1294');
script_set_attribute(attribute: 'see_also', value: 'http://tigger.uic.edu/~jlongs2/holes/tnftp.txt');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200501-24.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200501-24] tnftp: Arbitrary file overwriting');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'tnftp: Arbitrary file overwriting');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-ftp/tnftp", unaffected: make_list("ge 20050103"), vulnerable: make_list("lt 20050103")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
