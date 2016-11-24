# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200511-11.xml
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
 script_id(20198);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200511-11");
 script_cve_id("CVE-2005-3524");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200511-11 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200511-11
(linux-ftpd-ssl: Remote buffer overflow)


    A buffer overflow vulnerability has been found in the
    linux-ftpd-ssl package. A command that generates an excessively long
    response from the server may overrun a stack buffer.
  
Impact

    An attacker that has permission to create directories that are
    accessible via the FTP server could exploit this vulnerability.
    Successful exploitation would execute arbitrary code on the local
    machine with root privileges.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All ftpd users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-ftp/netkit-ftpd-0.17-r3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3524');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200511-11.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200511-11] linux-ftpd-ssl: Remote buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'linux-ftpd-ssl: Remote buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-ftp/netkit-ftpd", unaffected: make_list("ge 0.17-r3"), vulnerable: make_list("lt 0.17-r3")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
