# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200705-04.xml
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
 script_id(25154);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200705-04");
 script_cve_id("CVE-2007-1349");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200705-04 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200705-04
(Apache mod_perl: Denial of Service)


    Alex Solvey discovered that the "path_info" variable used in file
    RegistryCooker.pm (mod_perl 2.x) or file PerlRun.pm (mod_perl 1.x), is
    not properly escaped before being processed.
  
Impact

    A remote attacker could send a specially crafted URL to the vulnerable
    server, possibly resulting in a massive resource consumption.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All mod_perl 1.x users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apache/mod_perl-1.30"
    All mod_perl 2.x users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apache/mod_perl-2.0.3-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1349');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200705-04.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200705-04] Apache mod_perl: Denial of Service');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Apache mod_perl: Denial of Service');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apache/mod_perl", unaffected: make_list("ge 2.0.3-r1", "rge 1.30"), vulnerable: make_list("lt 2.0.3-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
