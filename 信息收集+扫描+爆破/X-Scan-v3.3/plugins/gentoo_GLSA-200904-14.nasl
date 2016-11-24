# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200904-14.xml
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
 script_id(36158);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200904-14");
 script_cve_id("CVE-2008-3243", "CVE-2008-3244", "CVE-2008-5747");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200904-14 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200904-14
(F-PROT Antivirus: Multiple Denial of Service vulnerabilities)


    The following vulnerabilities were found:
    Multiple errors when processing UPX, ASPack or Microsoft Office
    files (CVE-2008-3243).
    Infinite Sergio Alvarez of n.runs AG reported an invalid memory
    access when processing a CHM file with a large nb_dir value
    (CVE-2008-3244).
    Jonathan Brossard from iViZ Techno Solutions reported that F-PROT
    Antivirus does not correctly process ELF binaries with corrupted
    headers (CVE-2008-5747).
  
Impact

    A remote attacker could entice a user or automated system to scan a
    specially crafted file, leading to a crash or infinite loop.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All F-PROT Antivirus users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-antivirus/f-prot-6.0.2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3243');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3244');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5747');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200904-14.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200904-14] F-PROT Antivirus: Multiple Denial of Service vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'F-PROT Antivirus: Multiple Denial of Service vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-antivirus/f-prot", unaffected: make_list("ge 6.0.2"), vulnerable: make_list("lt 6.0.2")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
