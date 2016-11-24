# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200909-04.xml
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
 script_id(40912);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200909-04");
 script_cve_id("CVE-2008-6680", "CVE-2009-1270", "CVE-2009-1371", "CVE-2009-1372");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200909-04 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200909-04
(Clam AntiVirus: Multiple vulnerabilities)


    Multiple vulnerabilities have been found in ClamAV:
    The
    vendor reported a Divide-by-zero error in the PE ("Portable
    Executable"; Windows .exe) file handling of ClamAV
    (CVE-2008-6680).
    Jeffrey Thomas Peckham found a flaw in
    libclamav/untar.c, possibly resulting in an infinite loop when
    processing TAR archives in clamd and clamscan (CVE-2009-1270).
    Martin Olsen reported a vulnerability in the CLI_ISCONTAINED macro
    in libclamav/others.h, when processing UPack archives
    (CVE-2009-1371).
    Nigel disclosed a stack-based buffer overflow
    in the "cli_url_canon()" function in libclamav/phishcheck.c when
    processing URLs (CVE-2009-1372).
  
Impact

    A remote attacker could entice a user or automated system to process a
    specially crafted UPack archive or a file containing a specially
    crafted URL, possibly resulting in the remote execution of arbitrary
    code with the privileges of the user running the application, or a
    Denial of Service. Furthermore, a remote attacker could cause a Denial
    of Service by supplying a specially crafted TAR archive or PE
    executable to a Clam AntiVirus instance.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Clam AntiVirus users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose =app-antivirus/clamav-0.95.2
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-6680');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1270');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1371');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1372');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200909-04.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200909-04] Clam AntiVirus: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Clam AntiVirus: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-antivirus/clamav", unaffected: make_list("ge 0.95.2"), vulnerable: make_list("lt 0.95.2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
