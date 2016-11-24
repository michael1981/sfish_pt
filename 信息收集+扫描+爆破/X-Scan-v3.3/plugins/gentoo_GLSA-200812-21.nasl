# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200812-21.xml
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
 script_id(35268);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200812-21");
 script_cve_id("CVE-2008-5050", "CVE-2008-5314");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200812-21 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200812-21
(ClamAV: Multiple vulnerabilities)


    Moritz Jodeit reported an off-by-one error within the
    get_unicode_name() function in libclamav/vba_extract.c when processing
    VBA project files (CVE-2008-5050). Ilja van Sprundel reported an
    infinite recursion error within the cli_check_jpeg_exploit() function
    in libclamav/special.c when processing JPEG files (CVE-2008-5314).
  
Impact

    A remote attacker could send a specially crafted VBA or JPEG file to
    the clamd daemon, possibly resulting in the remote execution of
    arbitrary code with the privileges of the user running the application
    or a Denial of Service.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All ClamAV users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-antivirus/clamav-0.94.2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5050');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5314');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200812-21.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200812-21] ClamAV: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ClamAV: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-antivirus/clamav", unaffected: make_list("ge 0.94.2"), vulnerable: make_list("lt 0.94.2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
