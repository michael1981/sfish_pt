# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200803-01.xml
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
 script_id(31328);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200803-01");
 script_cve_id("CVE-2007-1199", "CVE-2007-5659", "CVE-2007-5663", "CVE-2007-5666", "CVE-2008-0655", "CVE-2008-0667", "CVE-2008-0726");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200803-01 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200803-01
(Adobe Acrobat Reader: Multiple vulnerabilities)


    Multiple vulnerabilities have been discovered in Adobe Acrobat Reader,
    including:
    A file disclosure when using file:// in PDF documents
    (CVE-2007-1199)
    Multiple buffer overflows in unspecified Javascript methods
    (CVE-2007-5659)
    An unspecified vulnerability in the Escript.api plugin
    (CVE-2007-5663)
    An untrusted search path (CVE-2007-5666)
    Incorrect handling of printers (CVE-2008-0667)
    An integer overflow when passing incorrect arguments to
    "printSepsWithParams" (CVE-2008-0726)
    Other unspecified vulnerabilities have also been reported
    (CVE-2008-0655).
  
Impact

    A remote attacker could entice a user to open a specially crafted
    document, possibly resulting in the remote execution of arbitrary code
    with the privileges of the user running the application. A remote
    attacker could also perform cross-site request forgery attacks, or
    cause a Denial of Service.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Adobe Acrobat Reader users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/acroread-8.1.2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1199');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5659');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5663');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5666');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0655');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0667');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0726');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200803-01.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200803-01] Adobe Acrobat Reader: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Adobe Acrobat Reader: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-text/acroread", unaffected: make_list("ge 8.1.2"), vulnerable: make_list("lt 8.1.2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
